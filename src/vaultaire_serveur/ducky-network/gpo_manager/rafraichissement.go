package gpomanager

import (
	"fmt"
	"strings"

	"vaultaire/core/logs"
	"vaultaire/ducky-network/sendmessage"
	"vaultaire/ducky-network/sessionmgr"
)

// Déclenchement d'un cycle GPO hors du tour périodique — trame 05_18.
//
// # La seule trame 05 que le serveur émet de lui-même
//
// Tout le reste de la catégorie 05 est tiré par le client : il demande, le
// serveur répond. Ce modèle a une conséquence qu'on ne voit qu'en
// exploitation — entre la modification d'une GPO et son application sur un
// poste, il s'écoule jusqu'à une cadence entière. Un administrateur qui
// corrige une règle de pare-feu fautive ne peut rien faire d'autre
// qu'attendre, ou raccourcir la cadence de tout le parc pour un seul poste.
//
// 05_18 dit « rafraîchis maintenant ». Elle ne transporte AUCUNE politique :
// l'agent refait sa demande 05_01 normale, et tout le chemin habituel — calcul
// côté serveur, empreinte, fragments, rapport — reste identique. Une trame de
// réveil ne pouvait pas devenir un second chemin d'application, qui aurait
// fallu tenir d'accord avec le premier.
//
// # Rien n'est mis en file
//
// Une machine hors ligne ne reçoit pas la trame et n'en garde aucune trace,
// contrairement à un ordre de révocation qui reste « pending » en base. C'est
// délibéré : une machine qui revient fait de toute façon un cycle à la
// reconnexion (voir surveillerReconnexion côté agent), donc rejouer la demande
// n'apporterait rien et ferait un cycle de plus.

// DemanderRafraichissement pousse 05_18 à une machine connectée.
//
// Rend faux si la machine n'a pas de session Ducky en cours — ce qui n'est pas
// une erreur mais un « pas maintenant » : l'appelant l'affiche, et la machine
// se rafraîchira en revenant.
func DemanderRafraichissement(computeurID, motif string) bool {
	sess, ok := sessionmgr.Sessions.GetByClientSoftwareID(computeurID)
	if !ok || sess.DuckySession == nil {
		return false
	}

	motif = strings.TrimSpace(motif)
	if motif == "" {
		motif = "demande administrateur"
	}

	trame := reply("05_18", sess.SessionID, motif)
	if err := sendmessage.SendMessage(trame, computeurID, sess.DuckySession); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeGPOTransport, fmt.Sprintf(
			"gpo: rafraichissement non remis à %s : %v", computeurID, err))
		return false
	}

	logs.Write_LogCode("INFO", logs.CodeGPOTransport, fmt.Sprintf(
		"gpo: rafraichissement demandé à %s (%s)", computeurID, motif))
	return true
}

// MachinesEnLigne rend les identifiants des machines actuellement connectées.
//
// Le parc joignable, et non le parc inscrit : une poussée ne peut atteindre
// qu'une session ouverte, et présenter les machines éteintes comme des cibles
// ferait annoncer un rafraîchissement qui n'aura pas lieu.
func MachinesEnLigne() []string {
	vus := map[string]bool{}
	var ids []string
	for _, sess := range sessionmgr.Sessions.ListAuthenticated() {
		id := strings.TrimSpace(sess.ClientSoftwareID)
		if id == "" || vus[id] {
			continue
		}
		vus[id] = true
		ids = append(ids, id)
	}
	return ids
}

// DemanderRafraichissementParc pousse 05_18 à toutes les machines d'une liste.
//
// Rend le nombre de machines jointes. Les autres sont simplement hors ligne :
// aucune erreur n'est remontée, pour que le déclenchement sur un parc entier
// n'échoue pas à cause d'un portable éteint.
func DemanderRafraichissementParc(computeurIDs []string, motif string) int {
	joint := 0
	for _, id := range computeurIDs {
		if DemanderRafraichissement(id, motif) {
			joint++
		}
	}
	return joint
}
