package miseajour

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"

	"vaultaire_client/config"
	"vaultaire_client/pamstate"
	"vaultaire_client/paquet"
)

// Appliquer, pour de vrai — TO-DO 116.
//
// L'ordre arrive dans le gestionnaire de trames, qui ne doit pas attendre un
// téléchargement de plusieurs dizaines de Mo ni un redémarrage. Appliquer prend
// donc le verrou, lance le déroulé en arrière-plan, et rend « en cours » : PAS
// de compte rendu immédiat. Le résultat est écrit dans l'état
// (/var/lib/vaultaire/updates/etat.json) par celui qui le connaît — l'agent
// s'il refuse, l'updater après la bascule —, et l'agent le rapporte en 09_04
// dès qu'il tient une session (SurveillerLesOrdres). Après une bascule réussie,
// c'est le NOUVEL agent qui le rapporte.

// EtalementMax : un tirage dans [0, EtalementMax) avant de télécharger. Une
// cible posée sur le parc atteint en une minute toutes les machines connectées
// (la poussée du core) : sans étalement, elles téléchargeraient ensemble.
var EtalementMax = 2 * time.Minute

// cheminsAgent : remplaçable par les tests.
var cheminsAgent = CheminsReels()

// cleDeSessionCourante : branchée par Configurer ; sert à demander les dépôts.
var cleDeSessionCourante = func() string { return "" }

// ConfigurerSession branche la clé de session, pour la découverte des dépôts.
func ConfigurerSession(cle func() string) { cleDeSessionCourante = cle }

// systemdDirige : remplaçable par les tests.
var systemdDirige = func() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func appliquerReel(o Ordre) (string, string) {
	if os.Geteuid() != 0 || !systemdDirige() {
		return ResultatNonPrisEnCharge, "l'agent ne tourne pas en root sous systemd : il ne peut pas se remplacer"
	}
	if !PrendreVerrou(cheminsAgent, o.Version) {
		logs.Write_log("INFO", "mise à jour : une mise à jour est déjà en cours, ordre "+o.Version+" ignoré")
		return "", ""
	}
	go func() {
		defer logs.Recover("mise à jour : déroulé")
		derouler(o)
	}()
	return "", ""
}

func derouler(o Ordre) {
	c := cheminsAgent
	attente := time.Duration(0)
	if EtalementMax > 0 {
		attente = time.Duration(rand.Int64N(int64(EtalementMax)))
	}
	logs.Write_log("INFO", fmt.Sprintf("mise à jour : %s dans %s (étalement)", o.Version, attente.Round(time.Second)))
	time.Sleep(attente)

	bases, err := Depots(cleDeSessionCourante)
	if err != nil {
		logs.Write_log("WARNING", "mise à jour : "+err.Error()+" — l'ordre sera redonné")
		LibererVerrou(c)
		return
	}
	client, err := ClientHTTP(config.GetUpdateTLSCA())
	if err != nil {
		refuser(c, o, err.Error())
		return
	}
	plan, err := Preparer(Preparation{
		Chemins: c, Systeme: SystemeReel, Telecharger: TelechargerAvec(client),
		Bases: bases, Cles: paquet.ClesDeConfiance,
	}, o)
	if err != nil {
		if errors.Is(err, ErrTransitoire) {
			logs.Write_log("WARNING", "mise à jour : "+err.Error()+" — l'ordre sera redonné")
			LibererVerrou(c)
			return
		}
		refuser(c, o, err.Error())
		return
	}
	logs.Write_log("INFO", "mise à jour : "+o.Version+" vérifiée (signature, empreintes, modules, --check) — bascule")
	if err := lancerUpdater(c, plan, SystemeReel); err != nil {
		_ = EcrireEtat(c, EtatFichier{Version: o.Version, Resultat: ResultatEchec,
			Motif: "updater non lancé : " + err.Error() + " — rien n'a changé"})
		LibererVerrou(c)
	}
	// Le verrou est désormais à l'updater, qui le rend en finissant.
}

func refuser(c Chemins, o Ordre, motif string) {
	logs.Write_log("WARNING", "mise à jour : "+o.Version+" refusée — "+motif)
	_ = EcrireEtat(c, EtatFichier{Version: o.Version, Resultat: ResultatRefuse, Motif: motif})
	LibererVerrou(c)
}

// lancerUpdater pose une COPIE de l'agent en place dans /usr/libexec/vaultaire/
// et la lance, détachée, dans une unité transitoire : elle survit au
// redémarrage du service qu'elle va provoquer.
func lancerUpdater(c Chemins, p Plan, sys Systeme) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.Updater), 0o755); err != nil {
		return err
	}
	if err := poser(exe, c.Updater, 0o750); err != nil {
		return fmt.Errorf("copie de l'updater : %w", err)
	}
	_, _ = sys("restorecon", "-F", c.Updater)
	sortie, err := sys("systemd-run", "--unit=vaultaire-update", "--collect", "--quiet",
		"--description=Mise à jour de l'agent Vaultaire", c.Updater, "--basculer", p.Repertoire)
	if err != nil {
		return fmt.Errorf("systemd-run : %v %s", err, premieresLignes(string(sortie), 2))
	}
	return nil
}

// ExecuterUpdater est le point d'entrée de « vaultaire_update --basculer » :
// rend le code de sortie.
func ExecuterUpdater(rep string) int {
	c := CheminsReels()
	absolu, err := filepath.Abs(rep)
	if err != nil || filepath.Dir(absolu) != c.Etat {
		fmt.Fprintf(os.Stderr, "--basculer : répertoire hors de %s\n", c.Etat)
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "--basculer : root exigé")
		return 2
	}
	p, err := LirePlan(absolu)
	if err != nil {
		_ = EcrireEtat(c, EtatFichier{Version: filepath.Base(absolu), Resultat: ResultatEchec, Motif: err.Error()})
		LibererVerrou(c)
		return 1
	}
	b := Bascule{
		Chemins: c, Systeme: SystemeReel, Service: ServiceSystemd(SystemeReel),
		Sonde:  SondeSocket(pamstate.SocketPath),
		Dormir: time.Sleep, Horloge: time.Now,
	}
	resultat, motif := b.Executer(p)
	fmt.Println(resultat + " : " + motif)
	if resultat != ResultatInstalle {
		return 1
	}
	return 0
}

// SondeSocket interroge le socket PAM de l'agent.
func SondeSocket(chemin string) func() (Pong, error) {
	return func() (Pong, error) {
		conn, err := net.DialTimeout("unix", chemin, 3*time.Second)
		if err != nil {
			return Pong{}, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(`{"ping":{}}` + "\n")); err != nil {
			return Pong{}, err
		}
		var r struct {
			Status string `json:"status"`
			Pong
		}
		if err := json.NewDecoder(conn).Decode(&r); err != nil {
			return Pong{}, fmt.Errorf("réponse illisible : %w", err)
		}
		if r.Status != "pong" {
			return Pong{}, fmt.Errorf("réponse %q", r.Status)
		}
		return r.Pong, nil
	}
}

// compteRenduEnAttente rend la 09_04 à envoyer, s'il y en a une.
func compteRenduEnAttente(c Chemins, cle string) (string, func()) {
	e, ok := LireEtat(c)
	if !ok || e.Rapporte {
		return "", nil
	}
	trame := CompteRendu(cle, e.Version, e.Resultat, e.Motif)
	return trame, func() {
		e.Rapporte = true
		if err := EcrireEtat(c, e); err != nil {
			logs.Write_log("WARNING", "mise à jour : état non marqué rapporté : "+err.Error())
		}
	}
}

func init() { Appliquer = appliquerReel }
