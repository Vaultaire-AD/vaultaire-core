package confsys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/enligne"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_client/config"
	"vaultaire_client/miseajour"
	"vaultaire_client/pamstate"
)

// Le passage au démarrage, l'état gardé, et le compte rendu 09_07.
//
// # Quand
//
// Une fois par démarrage de l'agent, et JAMAIS pendant une mise à jour : tant
// que le verrou du 116 est tenu, on attend. Après une bascule, le verrou est
// rendu par l'updater APRÈS la porte de santé ; si elle échoue, l'agent neuf
// est arrêté par le retour arrière avant d'avoir rien réconcilié. C'est la
// règle de la conception : la configuration n'est réconciliée qu'une fois la
// porte franchie, jamais dans la même opération.

// DossierEtat : l'état et les sauvegardes qui ne vont pas à côté de leur
// fichier.
const DossierEtat = "/var/lib/vaultaire/confsys"

// EtatFichier : le dernier passage, et s'il est parti au core.
type EtatFichier struct {
	Etat     string    `json:"etat"`
	Motif    string    `json:"motif"`
	Le       time.Time `json:"le"`
	Rapporte bool      `json:"rapporte"`
}

func cheminEtat(dossier string) string { return filepath.Join(dossier, "etat.json") }

// LireEtat rend le dernier état, false s'il n'y en a pas.
func LireEtat(dossier string) (EtatFichier, bool) {
	b, err := os.ReadFile(cheminEtat(dossier))
	if err != nil {
		return EtatFichier{}, false
	}
	var e EtatFichier
	if json.Unmarshal(b, &e) != nil || e.Etat == "" {
		return EtatFichier{}, false
	}
	return e, true
}

// Garder écrit l'état d'un passage. Le même constat que le précédent, déjà
// rapporté, reste rapporté : le core n'a pas à l'entendre à chaque démarrage.
func Garder(dossier string, r Rapport, maintenant time.Time) error {
	e := EtatFichier{Etat: r.Etat, Motif: r.Motif, Le: maintenant}
	if avant, ok := LireEtat(dossier); ok && avant.Rapporte && avant.Etat == e.Etat && avant.Motif == e.Motif {
		e.Rapporte = true
	}
	return ecrireEtat(dossier, e)
}

func ecrireEtat(dossier string, e EtatFichier) error {
	if err := os.MkdirAll(dossier, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp := cheminEtat(dossier) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, cheminEtat(dossier))
}

// CompteRendu compose la 09_07. Le motif tient sur une ligne, borné.
func CompteRendu(sessionKey, etat, motif string) string {
	motif = strings.ReplaceAll(strings.ReplaceAll(motif, "\r", " "), "\n", " ")
	if r := []rune(motif); len(r) > 240 {
		motif = string(r[:240])
	}
	return strings.Join([]string{
		"09_07", "serveur_central", sessionKey, pamstate.Username, storage.Computeur_ID, etat, motif,
	}, "\n")
}

// --- le branchement dans l'agent --------------------------------------------

var (
	envoyerMu sync.RWMutex
	envoyer   func(trame string)
)

// Configure branche l'émetteur des trames.
func Configure(f func(trame string)) {
	envoyerMu.Lock()
	envoyer = f
	envoyerMu.Unlock()
}

func emettre(trame string) bool {
	envoyerMu.RLock()
	f := envoyer
	envoyerMu.RUnlock()
	if f == nil {
		return false
	}
	f(trame)
	return true
}

// coreSait : la 09_07 n'est émise que vers un core qui annonce la capacité —
// un core plus ancien fermerait la connexion. Remplaçable par les tests.
var coreSait = func() bool { return enligne.CoreSait(enligne.CapaciteConfSys) }

// Variables du lancement, remplaçables par les tests.
var (
	dossierEtat = DossierEtat
	majEnCours  = func() bool { return miseajour.VerrouTenu(miseajour.CheminsReels()) }
	pasDAttente = 5 * time.Second
	envReel     = func() (Env, error) {
		osr, err := os.ReadFile("/etc/os-release")
		if err != nil {
			return Env{}, fmt.Errorf("os-release illisible : %w", err)
		}
		f, err := miseajour.FamilleDe(string(osr))
		if err != nil {
			return Env{}, err
		}
		return Env{Famille: f, Systeme: Systeme(miseajour.SystemeReel), Horloge: time.Now,
			DossierSauvegardes: filepath.Join(DossierEtat, "sauvegardes")}, nil
	}
	estRoot = func() bool { return os.Geteuid() == 0 }
)

// Passage : le passage du démarrage — attendre la fin d'une mise à jour,
// réconcilier, journaliser, garder l'état.
func Passage() Rapport {
	r := passage()
	niveau := "INFO"
	if r.Etat == EtatEcart {
		niveau = "WARNING"
	}
	logs.Write_log(niveau, "configuration système : "+r.Etat+" — "+r.Motif)
	if err := Garder(dossierEtat, r, time.Now()); err != nil {
		logs.Write_log("WARNING", "configuration système : état non gardé : "+err.Error())
	}
	return r
}

func passage() Rapport {
	if !config.GetReconcileSystemConfig() {
		return Rapport{Etat: EtatDesactivee, Motif: "reconcile_system_config: false dans client_conf.json"}
	}
	if !estRoot() {
		return Rapport{Etat: EtatNonPrisEnCharge, Motif: "l'agent ne tourne pas en root"}
	}
	for majEnCours() {
		time.Sleep(pasDAttente)
	}
	e, err := envReel()
	if err != nil {
		return Rapport{Etat: EtatNonPrisEnCharge, Motif: err.Error()}
	}
	return Reconcilier(e)
}

// Demarrer : le passage, puis le compte rendu dès qu'une session le permet.
// Ne rend jamais la main : à lancer dans une goroutine.
func Demarrer(cleDeSession func() string) {
	Passage()
	for {
		if cle := cleDeSession(); cle != "" && coreSait() {
			if e, ok := LireEtat(dossierEtat); ok && !e.Rapporte {
				if emettre(CompteRendu(cle, e.Etat, e.Motif)) {
					e.Rapporte = true
					if err := ecrireEtat(dossierEtat, e); err != nil {
						logs.Write_log("WARNING", "configuration système : état non marqué rapporté : "+err.Error())
					}
				}
			}
		}
		time.Sleep(pasDAttente)
	}
}

// Etat : pour « vaultaire_client --config-status » — ce que le passage
// ferait, sans rien écrire. Rend le texte et s'il reste quelque chose à faire.
func Etat() (string, bool) {
	e, err := envReel()
	if err != nil {
		return "configuration système : " + err.Error() + "\n", true
	}
	r, _, err := Planifier(e)
	if err != nil {
		return "configuration système : " + err.Error() + "\n", true
	}
	if k := ControlerSSHDEffectif(e); k != nil {
		r.Constats = append(r.Constats, *k)
	}
	return Afficher(r, e.Famille), resteAFaire(r)
}

func resteAFaire(r Rapport) bool {
	for _, k := range r.Constats {
		if k.Action == ActionAEcrire || k.Action == ActionRefuse || k.Action == ActionEcartEffectif {
			return true
		}
	}
	return false
}

// Afficher met un rapport en forme pour un terminal.
func Afficher(r Rapport, famille string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Configuration système (famille %s) — tenue par l'agent, TO-DO 117\n\n", famille)
	for _, k := range r.Constats {
		ligne := fmt.Sprintf("  %-36s v%d / attendu v%d   %s", k.Nom, k.Avant, k.Attendue, k.Action)
		if k.Action == ActionEcartEffectif {
			// Pas une version de fichier : ce que sshd applique (TO-DO 209).
			ligne = fmt.Sprintf("  %-36s %s", k.Nom, k.Action)
		}
		if k.Detail != "" {
			ligne += " — " + k.Detail
		}
		b.WriteString(ligne + "\n")
	}
	if e, ok := LireEtat(dossierEtat); ok {
		fmt.Fprintf(&b, "\nDernier passage (%s) : %s — %s\n", e.Le.Format("2006-01-02 15:04"), e.Etat, e.Motif)
	}
	return b.String()
}
