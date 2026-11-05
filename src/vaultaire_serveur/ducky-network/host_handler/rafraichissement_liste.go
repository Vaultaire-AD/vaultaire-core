package hosthandler

import (
	"fmt"
	"strings"

	"vaultaire/core/logs"
	"vaultaire/ducky-network/sendmessage"
	"vaultaire/ducky-network/sessionmgr"
	"vaultaire/ducky-network/trame"
)

// Demander à une machine de redemander sa liste de nœuds — trame 04_17.
//
// # Pourquoi une poussée, alors que la liste a déjà une cadence
//
// La cadence (`node_list_refresh_minutes`, ligne « disco: » de 04_04) borne le
// retard : au pire une demi-heure entre l'ajout d'un core et sa prise en compte
// par un poste. C'est acceptable en régime normal et beaucoup trop long pendant
// une bascule de cluster, où l'on veut que le parc suive tout de suite.
//
// Raccourcir la cadence pour tout le parc à cause d'un moment particulier
// reviendrait à faire redemander la liste toutes les minutes pendant l'année
// entière, pour les dix minutes qui comptent.
//
// # Elle ne transporte AUCUNE liste
//
// L'agent repart sur une 04_03 ordinaire, et tout le chemin habituel — filtrage
// par ses groupes, tri, apprentissage des empreintes, persistance — reste
// identique. Une trame de réveil ne pouvait pas devenir un second chemin
// d'apprentissage, qu'il aurait fallu tenir d'accord avec le premier. C'est le
// même arbitrage que pour 05_18 côté GPO.
//
// # Rien n'est mis en file
//
// Une machine hors ligne ne la reçoit pas et n'en garde aucune trace. Elle
// redemandera sa liste à sa reconnexion, parce que la boucle de découverte
// commence par un passage immédiat : rejouer la demande ne ferait qu'un
// aller-retour de plus.

// PrefixeQuitter ouvre, dans une 04_17, une ligne « quitter <hôte:port> » :
// le nœud que la machine doit quitter (TO-DO 216).
//
// # Pourquoi la liste ne suffisait pas
//
// La 04_17 de la purge (147, 176) comptait sur la liste redemandée : le nœud en
// maintenance n'y figure plus, et la bascule (bascule.go côté agent) fait
// partir l'agent. Deux cas la défont :
//
//   - la liste revient VIDE (aucun autre nœud exposé) : l'agent garde
//     l'ancienne — c'est voulu, une liste vide ne dit rien — et ne bascule pas ;
//   - sa session fermée par la purge, l'agent se reconnecte dans l'ordre de la
//     liste qu'il a EN MAIN, où le nœud purgé est encore premier, et y revient.
//
// Nommer le nœud règle les deux : l'agent le quitte, et le place en DERNIER
// pendant un temps — il reste joignable s'il est le seul, comme le veut le
// 177. Un agent antérieur lit ces lignes comme la suite du motif, et ne fait
// rien de plus qu'avant.
const PrefixeQuitter = "quitter "

// DemanderActualisationListe pousse 04_17 à une machine connectée.
//
// quitter : les « hôte:port » d'un nœud que la machine doit quitter, à nommer
// dans la trame — vide pour une simple actualisation.
//
// Rend (vrai, nil) si la trame est partie ; (faux, nil) si la machine n'a pas
// de tunnel en cours — ce n'est pas une erreur, mais un « pas maintenant » ;
// (faux, err) si un tunnel existe mais qu'aucun envoi n'a abouti. Les confondre
// laisserait l'administrateur, devant une machine visiblement connectée, sans
// moyen de savoir s'il doit attendre ou chercher un défaut.
func DemanderActualisationListe(computeurID, motif string, quitter ...string) (bool, error) {
	candidates := sessionmgr.Sessions.SessionsMachine(computeurID, sessionmgr.FraicheurTunnel())
	if len(candidates) == 0 {
		return false, nil
	}

	motif = strings.TrimSpace(motif)
	if motif == "" {
		motif = "demande administrateur"
	}

	contenu := ContenuActualisation(motif, quitter)

	var derniere error
	for _, sess := range candidates {
		msg := trame.ReponseClient("04_17", "serveur_central", sess.SessionID, contenu...)
		if err := sendmessage.SendMessage(msg, sess.ClientSoftwareID, sess.DuckySession); err != nil {
			derniere = err
			logs.Write_Log("DEBUG", fmt.Sprintf(
				"cluster: actualisation de liste non remise à %s par la session %s : %v",
				sess.ClientSoftwareID, sess.SessionID, err))
			continue
		}
		logs.Write_Log("INFO", fmt.Sprintf(
			"cluster: actualisation de la liste demandée à %s (%s)", sess.ClientSoftwareID, motif))
		return true, nil
	}

	logs.Write_Log("WARNING", fmt.Sprintf(
		"cluster: actualisation de liste non remise à %s : %d session(s) essayée(s), dernière erreur : %v",
		computeurID, len(candidates), derniere))
	return false, fmt.Errorf("%d session(s) du tunnel essayée(s), aucun envoi n'a abouti : %v",
		len(candidates), derniere)
}

// MachinesEnLigne rend les identifiants des machines actuellement connectées.
//
// Le tunnel de la MACHINE seulement : une session d'utilisateur porte aussi
// l'identifiant du poste, mais ce n'est pas elle qui reçoit les trames de
// cluster. La compter annoncerait comme joignable une machine sans tunnel.
func MachinesEnLigne() []string {
	vus := map[string]bool{}
	var ids []string
	for _, sess := range sessionmgr.Sessions.ListAuthenticated() {
		if sess.Username != sessionmgr.CompteMachine {
			continue
		}
		id := strings.TrimSpace(sess.ClientSoftwareID)
		if id == "" || vus[id] {
			continue
		}
		vus[id] = true
		ids = append(ids, id)
	}
	return ids
}

// ContenuActualisation compose le contenu d'une 04_17 : le motif, puis une
// ligne « quitter » par accès à quitter.
func ContenuActualisation(motif string, quitter []string) []string {
	contenu := []string{motif}
	for _, a := range quitter {
		if a = strings.TrimSpace(a); a != "" && !strings.ContainsAny(a, "\n\r") {
			contenu = append(contenu, PrefixeQuitter+a)
		}
	}
	return contenu
}
