// Package chrono mesure l'ouverture d'une session, en mode debug seulement —
// TO-DO 199.
//
// # Pourquoi un journal à part
//
// Le rapport du 190 l'a constaté : on ne pouvait pas dire où passaient les
// 20 s d'une connexion SSH. vaultaire_pam.log n'a pas d'heure, vaultaire.log
// est à la seconde, et la seule durée journalisée était celle du cycle GPO.
//
// Ce paquet écrit une ligne par étape mesurée, en millisecondes, dans un
// fichier DÉDIÉ — vlt_client-Debug-connexions.log, à côté du rapport de debug
// (vlt_client-Debug.log). Le journal ordinaire et son format, communs au proxy
// et au core, ne bougent pas.
//
// # Seulement en mode debug
//
// Le même interrupteur que le rapport de debug : `-debug` au lancement de
// l'agent, ou "debug": {"enabled": true} dans client_conf.json. Hors debug,
// rien n'est mesuré ni écrit.
//
// Le module PAM écrit dans le même fichier ses propres durées — la saisie de
// la personne, l'attente de l'agent — quand la réponse de l'agent porte
// "chrono": true. C'est ainsi qu'il sait, sans fichier témoin, que le mode
// debug est actif.
package chrono

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// NomFichier est le nom du journal, sous storage.LogPathResolu(). Le module PAM
// écrit dans le même (VAULTAIRE_CHRONO_PATH, pam_common.h) : les deux doivent
// changer ensemble.
const NomFichier = "vlt_client-Debug-connexions.log"

// TailleMax borne le journal ; au-delà il est renommé en .1.
var TailleMax int64 = 20 << 20

var (
	actif atomic.Bool
	mu    sync.Mutex
	// chemin est une variable pour les tests.
	chemin = func() string { return filepath.Join(storage.LogPathResolu(), NomFichier) }
	// maintenant est une variable pour les tests.
	maintenant = time.Now
)

// Activer allume ou éteint la mesure. Appelé une fois, au démarrage.
func Activer(oui bool) { actif.Store(oui) }

// Actif dit si la mesure est allumée.
func Actif() bool { return actif.Load() }

// Ms rend une durée en millisecondes entières, pour l'affichage.
func Ms(d time.Duration) int64 { return d.Milliseconds() }

// Ecrire ajoute une ligne horodatée à la milliseconde. Sans effet hors debug.
//
// Une erreur d'écriture est avalée : une mesure perdue ne doit rien empêcher,
// et ce journal n'a nulle part où se plaindre que dans lui-même.
func Ecrire(format string, args ...any) {
	if !Actif() {
		return
	}
	ligne := maintenant().Format("2006-01-02 15:04:05.000") + " " + fmt.Sprintf(format, args...) + "\n"

	mu.Lock()
	defer mu.Unlock()
	c := chemin()
	// Pas de rotation quotidienne pour un journal de mesure : une borne de
	// taille, et l'ancien fichier gardé une fois (.1). Une ligne fait moins
	// de 200 octets ; la borne n'est atteinte qu'en laissant le debug allumé
	// des semaines sur un poste très fréquenté.
	if st, err := os.Lstat(c); err == nil && st.Mode().IsRegular() && st.Size() > TailleMax {
		_ = os.Rename(c, c+".1")
	}
	// 0600, comme les autres journaux de l'agent : il nomme des comptes.
	f, err := os.OpenFile(c, os.O_WRONLY|os.O_CREATE|os.O_APPEND|sansLien, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(ligne)
}
