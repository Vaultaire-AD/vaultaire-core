package module

import (
	"sync"
	"time"
)

// Connexion courante du tunnel machine : à quel nœud, depuis quand, et la
// dernière tentative manquée. Rien ne le retenait — l'adresse choisie ne vivait
// que dans une ligne de journal —, et le rapport de debug doit pouvoir dire
// « connecté à core-b depuis 14h02 » sans relire les journaux.

// EtatConnexion décrit la dernière connexion établie et le dernier échec.
type EtatConnexion struct {
	Adresse        string    // « ip:port » du nœud joint
	Depuis         time.Time // heure de l'établissement
	Essayees       []string  // adresses dans l'ordre tenté lors du dernier établissement
	DernierEchec   string    // adresse et motif du dernier échec
	DernierEchecA  time.Time
	Etablissements int // nombre de connexions établies depuis le démarrage
}

var (
	etatMu sync.Mutex
	etat   EtatConnexion
)

// Etat rend une copie de l'état de connexion.
func Etat() EtatConnexion {
	etatMu.Lock()
	defer etatMu.Unlock()
	e := etat
	e.Essayees = append([]string(nil), etat.Essayees...)
	return e
}

func noterSucces(adresse string, essayees []string) {
	etatMu.Lock()
	etat.Adresse = adresse
	etat.Depuis = time.Now()
	etat.Essayees = append([]string(nil), essayees...)
	etat.Etablissements++
	etatMu.Unlock()
}

func noterEchec(adresse string, err error) {
	etatMu.Lock()
	etat.DernierEchec = adresse + " : " + err.Error()
	etat.DernierEchecA = time.Now()
	etatMu.Unlock()
}
