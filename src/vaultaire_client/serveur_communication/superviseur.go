package serveurcommunication

import (
	"fmt"
	"sync/atomic"
	"time"

	"duckynetworkclient/V1/backoff"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
)

// Supervision du tunnel machine (`vaultaire`).
//
// # Ce que ce fichier corrige
//
// La boucle de connexion (EnableServerCommunication) reconnecte déjà après une
// coupure. Trois défauts la laissaient pourtant mourir ou se dédoubler :
//
//   - elle n'était lancée au démarrage que sur un nœud SERVEUR. Sur un poste, le
//     tunnel naissait à la première authentification PAM : une machine sur
//     laquelle personne ne se connecte n'appliquait ni GPO ni révocation, et
//     n'apparaissait pas dans `status -c` ;
//   - chaque authentification PAM qui trouvait le tunnel en cours de
//     rétablissement en lançait une SECONDE boucle. Plusieurs tunnels
//     `vaultaire` coexistaient alors, et chacun réécrivait la clé de session de
//     la machine côté core ;
//   - une panique dans la boucle (hors lecture de connexion, déjà protégée)
//     la terminait pour de bon : logs.Go rattrape la panique, mais ne relance
//     rien.
//
// DemarrerTunnelMachine est désormais le SEUL point de lancement : une fois
// par processus, et relancé après toute sortie.

var tunnelDemarre atomic.Bool

// DemarrerTunnelMachine lance la supervision du tunnel machine, une seule fois
// par processus. Les appels suivants ne font rien : le tunnel est déjà tenu.
func DemarrerTunnelMachine() {
	if !tunnelDemarre.CompareAndSwap(false, true) {
		return
	}
	logs.Go("tunnel machine", superviserTunnel)
}

// TunnelSupervise dit si la supervision a été lancée (tests, diagnostic).
func TunnelSupervise() bool { return tunnelDemarre.Load() }

// executerBoucle est une variable pour que les tests remplacent la boucle
// réelle, qui ouvre des connexions.
var executerBoucle = func() { EnableServerCommunication("vaultaire", "vaultaire") }

// pause est une variable pour que les tests n'attendent pas.
var pause = time.Sleep

func superviserTunnel() {
	attente := backoff.New()
	for {
		sortieNormale := func() (ok bool) {
			defer func() {
				if r := recover(); r != nil {
					logs.Write_log("CRITICAL", fmt.Sprintf("tunnel machine : panique dans la boucle de connexion : %v", r))
					ok = false
				}
			}()
			executerBoucle()
			return true
		}()

		if !storage.Persistent {
			// Mode une-passe (fetch-key) : pas de relance.
			return
		}
		d := attente.Prochain()
		if sortieNormale {
			logs.Write_log("WARNING", fmt.Sprintf("tunnel machine : boucle de connexion terminée, relance dans %s", d))
		} else {
			logs.Write_log("ERROR", fmt.Sprintf("tunnel machine : boucle relancée dans %s après panique", d))
		}
		pause(d)
	}
}
