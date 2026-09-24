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

// DemanderActualisationListe pousse 04_17 à une machine connectée.
//
// Rend (vrai, nil) si la trame est partie ; (faux, nil) si la machine n'a pas
// de tunnel en cours — ce n'est pas une erreur, mais un « pas maintenant » ;
// (faux, err) si un tunnel existe mais qu'aucun envoi n'a abouti. Les confondre
// laisserait l'administrateur, devant une machine visiblement connectée, sans
// moyen de savoir s'il doit attendre ou chercher un défaut.
func DemanderActualisationListe(computeurID, motif string) (bool, error) {
	candidates := sessionmgr.Sessions.SessionsMachine(computeurID, sessionmgr.FraicheurTunnel())
	if len(candidates) == 0 {
		return false, nil
	}

	motif = strings.TrimSpace(motif)
	if motif == "" {
		motif = "demande administrateur"
	}

	var derniere error
	for _, sess := range candidates {
		msg := trame.ReponseClient("04_17", "serveur_central", sess.SessionID, motif)
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
