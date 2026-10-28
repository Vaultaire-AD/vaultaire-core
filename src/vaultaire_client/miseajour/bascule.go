package miseajour

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// La bascule — ce que fait vaultaire_update (§ 6 de Mise_a_jour_du_parc.md).
//
//	garder la version en place → basculer par rename() → réécrire l'unité
//	→ redémarrer → PORTE DE SANTÉ → retour arrière si elle échoue
//
// # Qui exécute ce code
//
// Une COPIE de l'agent en place, posée dans /usr/libexec/vaultaire/ et lancée
// par systemd-run, dans une unité transitoire : le programme qui remplace un
// fichier ne peut pas être ce fichier, et il doit survivre au redémarrage du
// service. C'est donc toujours l'updater de la version COURANTE qui installe
// la suivante — celui dont on sait qu'il tourne sur cette machine.
//
// # Ce qu'il ne touche jamais
//
// La configuration système (point 117, après la porte de santé), /etc/
// vaultaire_client/ (identité et clés), /var/lib/vaultaire/applied_policies.json.
// Le plan ne nomme que les cinq fichiers et l'unité ; rien d'autre n'est écrit
// hors de son propre répertoire.

// Service : ce que la porte de santé lit de l'unité.
type Service struct {
	Actif bool
	PID   int
}

// Pong : la réponse de l'agent à la sonde du socket PAM.
type Pong struct {
	Version string `json:"version"`
	Tunnel  bool   `json:"tunnel"`
}

// Bascule : ce dont la bascule a besoin. Tout est remplaçable par les tests.
type Bascule struct {
	Chemins Chemins
	Systeme Systeme
	Service func() (Service, error)
	Sonde   func() (Pong, error)
	Dormir  func(time.Duration)
	Horloge func() time.Time
}

// Délais de la porte de santé. Variables, pour les tests.
var (
	// DelaiSante borne toute la porte : au-delà, retour arrière.
	DelaiSante = 3 * time.Minute
	// Stabilite : le service doit garder le même PID au-delà de la fenêtre
	// de relance (RestartSec=5s, trois essais) — sinon « actif » peut être un
	// démarrage entre deux plantages.
	Stabilite = 30 * time.Second
	// PasSante : l'intervalle entre deux lectures.
	PasSante = 2 * time.Second
)

// NomUnite : le service de l'agent.
const NomUnite = "vaultaire_client"

// LirePlan relit le plan écrit par l'agent.
func LirePlan(rep string) (Plan, error) {
	b, err := os.ReadFile(filepath.Join(rep, NomPlan))
	if err != nil {
		return Plan{}, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return Plan{}, fmt.Errorf("plan illisible : %w", err)
	}
	if len(p.Fichiers) != 5 || p.Version == "" || p.Binaire == "" {
		return Plan{}, fmt.Errorf("plan incomplet")
	}
	return p, nil
}

// Executer joue la bascule d'un plan, écrit l'état, et rend le résultat.
// Le verrou pris par l'agent est rendu à la fin, quoi qu'il arrive.
func (b Bascule) Executer(p Plan) (resultat, motif string) {
	defer LibererVerrou(b.Chemins)
	resultat, motif = b.executer(p)
	if err := EcrireEtat(b.Chemins, EtatFichier{Version: p.Version, Resultat: resultat, Motif: motif}); err != nil {
		logs.Write_log("ERROR", "mise à jour : état non écrit : "+err.Error())
	}
	return resultat, motif
}

func (b Bascule) executer(p Plan) (string, string) {
	debut := b.Horloge()
	logs.Write_log("INFO", fmt.Sprintf("mise à jour : bascule vers %s (%s)", p.Version, p.Famille))

	// 0. Les sources sont-elles toujours celles que l'agent a vérifiées ?
	for _, f := range p.Fichiers {
		if s, err := sommeDe(f.Source); err != nil || s != f.SHA256 {
			return ResultatRefuse, "fichier préparé modifié ou absent : " + f.Nom
		}
	}

	// 1. Garder la version en place. Un fichier en place ABSENT arrête tout :
	// sans lui, pas de retour arrière possible.
	precedent := filepath.Join(p.Repertoire, "precedent")
	_ = os.RemoveAll(precedent)
	if err := os.MkdirAll(precedent, 0o700); err != nil {
		return ResultatEchec, "garde impossible : " + err.Error()
	}
	for _, f := range p.Fichiers {
		if err := copier(f.Destination, filepath.Join(precedent, f.Nom)); err != nil {
			return ResultatRefuse, "version en place incomplète, rien n'est touché : " + err.Error()
		}
	}
	uniteGardee := filepath.Join(precedent, "unite.service")
	_ = copier(p.Unite, uniteGardee) // absente : rien à remettre

	// 2. Basculer, fichier par fichier ; au premier échec, on remet ce qui a
	// déjà basculé.
	for i, f := range p.Fichiers {
		if err := poserFichier(f.Source, f.Destination, f.Mode); err != nil {
			motif := fmt.Sprintf("bascule de %s : %v", f.Nom, err)
			b.remettre(p, i)
			return ResultatEchec, motif + " — rien n'a changé"
		}
	}
	b.etiqueter(p)

	// 3. L'unité : c'est le NOUVEAU binaire qui l'écrit (TO-DO 112), et un
	// binaire ancien refuserait de démarrer sous l'unité nouvelle — d'où la
	// copie gardée en 1, remise avec les fichiers au retour arrière.
	if sortie, err := b.Systeme(p.Binaire, "--install-unit"); err != nil {
		return b.retourArriere(p, "l'unité n'a pas pu être écrite : "+premieresLignes(string(sortie), 2))
	}

	// 4. Redémarrer, 5. porte de santé.
	_, _ = b.Systeme("systemctl", "reset-failed", NomUnite)
	if sortie, err := b.Systeme("systemctl", "restart", NomUnite); err != nil {
		return b.retourArriere(p, "redémarrage refusé : "+premieresLignes(string(sortie), 2))
	}
	if err := b.porteDeSante(true); err != nil {
		return b.retourArriere(p, err.Error())
	}

	_ = os.RemoveAll(filepath.Join(p.Repertoire, "nouveau"))
	motif := fmt.Sprintf("porte de santé franchie en %s", b.Horloge().Sub(debut).Round(time.Second))
	logs.Write_log("INFO", "mise à jour : "+p.Version+" en place — "+motif)
	return ResultatInstalle, motif
}

// remettre rend leur version gardée aux n premiers fichiers.
func (b Bascule) remettre(p Plan, n int) []string {
	var echecs []string
	for _, f := range p.Fichiers[:n] {
		if err := poser(filepath.Join(p.Repertoire, "precedent", f.Nom), f.Destination, f.Mode); err != nil {
			echecs = append(echecs, f.Nom+" : "+err.Error())
		}
	}
	return echecs
}

// retourArriere remet les cinq fichiers et l'unité, redémarre, et vérifie que
// l'ancienne version TIENT — sans la sonde, qu'un agent antérieur au 116 ne
// connaît pas.
func (b Bascule) retourArriere(p Plan, cause string) (string, string) {
	logs.Write_log("ERROR", "mise à jour : "+p.Version+" refusée par la porte de santé ("+cause+") — retour arrière")
	echecs := b.remettre(p, len(p.Fichiers))
	uniteGardee := filepath.Join(p.Repertoire, "precedent", "unite.service")
	if _, err := os.Stat(uniteGardee); err == nil {
		if err := poser(uniteGardee, p.Unite, 0o644); err != nil {
			echecs = append(echecs, "unité : "+err.Error())
		}
	}
	b.etiqueter(p)
	_, _ = b.Systeme("systemctl", "daemon-reload")
	_, _ = b.Systeme("systemctl", "reset-failed", NomUnite)
	_, _ = b.Systeme("systemctl", "restart", NomUnite)

	motif := "revenue en arrière : " + cause
	if len(echecs) > 0 {
		motif += " — RETOUR ARRIÈRE INCOMPLET : " + strings.Join(echecs, " ; ")
	} else if err := b.porteDeSante(false); err != nil {
		motif += " — et l'ancienne version NE TIENT PAS : " + err.Error()
	}
	if strings.Contains(motif, "INCOMPLET") || strings.Contains(motif, "NE TIENT PAS") {
		logs.Write_log("CRITICAL", "mise à jour : "+motif+" — fichiers gardés dans "+
			filepath.Join(p.Repertoire, "precedent"))
	}
	return ResultatEchec, motif
}

// porteDeSante : trois conditions, sous une échéance (§ 6.3).
//
//  1. le service tient — même PID au-delà de Stabilite ;
//  2. le tunnel est rétabli et authentifié ;
//  3. le socket PAM répond à une sonde sans identifiants.
//
// 2 et 3 viennent de la même sonde : elle traverse le socket et le traitement
// de la requête, et l'agent y dit s'il tient un tunnel. La troisième est celle
// qui compte : les deux premières ne disent rien du chemin dont dépendent
// toutes les ouvertures de session.
func (b Bascule) porteDeSante(avecSonde bool) error {
	echeance := b.Horloge().Add(DelaiSante)
	pid := 0
	var depuis time.Time
	derniere := "le service n'a pas démarré"
	for b.Horloge().Before(echeance) {
		s, err := b.Service()
		switch {
		case err != nil:
			derniere, pid = "état du service illisible : "+err.Error(), 0
		case !s.Actif || s.PID <= 0:
			derniere, pid = "le service n'est pas actif", 0
		default:
			if s.PID != pid {
				pid, depuis = s.PID, b.Horloge()
			}
			if b.Horloge().Sub(depuis) < Stabilite {
				derniere = "le service vient de (re)démarrer"
				break
			}
			if !avecSonde {
				return nil
			}
			pong, err := b.Sonde()
			switch {
			case err != nil:
				derniere = "le socket PAM ne répond pas : " + err.Error()
			case !pong.Tunnel:
				derniere = "le tunnel n'est pas rétabli"
			default:
				return nil
			}
		}
		b.Dormir(PasSante)
	}
	return fmt.Errorf("%s (échéance de %s)", derniere, DelaiSante)
}

// etiqueter remet les étiquettes SELinux des fichiers posés — rocky.sh le fait
// à l'installation : l'agent doit porter vaultaire_exec_t. Sans SELinux, sans
// effet.
func (b Bascule) etiqueter(p Plan) {
	args := []string{"-F"}
	for _, f := range p.Fichiers {
		args = append(args, f.Destination)
	}
	_, _ = b.Systeme("restorecon", args...)
}

// poserFichier : la pose de la bascule, remplaçable par les tests (un disque
// plein au troisième fichier ne se simule pas autrement).
var poserFichier = poser

// poser copie src dans le répertoire de dst sous un nom temporaire, puis
// rename() — atomique parce que dans le MÊME système de fichiers. Un .so déjà
// chargé par un processus vivant n'est pas affecté : l'ancien inode reste
// projeté, les sessions en cours continuent.
func poser(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".vaultaire-update-*")
	if err != nil {
		return err
	}
	nom := tmp.Name()
	_, errC := io.Copy(tmp, in)
	errS := tmp.Sync()
	errF := tmp.Close()
	if errC != nil || errS != nil || errF != nil {
		_ = os.Remove(nom)
		return fmt.Errorf("copie : %v %v %v", errC, errS, errF)
	}
	if err := os.Chmod(nom, mode); err != nil {
		_ = os.Remove(nom)
		return err
	}
	if err := os.Rename(nom, dst); err != nil {
		_ = os.Remove(nom)
		return err
	}
	return nil
}

// copier : copie simple, mode gardé — pour la garde.
func copier(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, errC := io.Copy(out, in)
	if errF := out.Close(); errC != nil || errF != nil {
		return fmt.Errorf("copie de %s : %v %v", src, errC, errF)
	}
	return nil
}

// ServiceSystemd lit l'état de l'unité par systemctl show.
func ServiceSystemd(sys Systeme) func() (Service, error) {
	return func() (Service, error) {
		sortie, err := sys("systemctl", "show", NomUnite, "-p", "ActiveState", "-p", "MainPID")
		if err != nil {
			return Service{}, err
		}
		var s Service
		for _, l := range strings.Split(string(sortie), "\n") {
			k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
			switch k {
			case "ActiveState":
				s.Actif = v == "active"
			case "MainPID":
				s.PID, _ = strconv.Atoi(v)
			}
		}
		return s, nil
	}
}
