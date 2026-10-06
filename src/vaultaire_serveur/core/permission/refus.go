package permission

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
)

// Le refus explicite : la valeur « deny » (TO-DO 104).
//
// # Le défaut
//
// La valeur « nil » était lue dans un champ nommé Deny, et la fiche la
// présentait comme « refusé ». Mais à l'évaluation, un groupe à « nil » était
// simplement SAUTÉ : si un autre groupe du compte accordait, c'était accordé.
// Un exploitant qui croyait retirer un droit en posant « nil » ne retirait rien
// tant que la cible appartenait à un autre groupe permissif.
//
// # Ce qui a été tranché
//
// Rendre « nil » prioritaire était exclu : c'est la valeur PAR DÉFAUT de toute
// action jamais renseignée. Une permission naît à « nil » partout ; la rendre
// prioritaire aurait retiré, à la mise à jour, presque tous les droits du parc
// à quiconque appartient à plus d'un groupe.
//
// D'où deux valeurs :
//
//   - « nil » reste ce qu'il faisait : RIEN d'accordé, et ignoré. Il est
//     désormais présenté comme tel (« aucun droit »), plus comme un refus ;
//   - « deny » est NOUVEAU : un refus explicite, qui l'emporte sur tout ce que
//     les autres groupes du compte accordent, « all » compris.
//
// « deny » vaut pour TOUS les domaines : c'est une valeur d'action, au même
// rang que « all ». Une permission à « deny » sur une action retire cette
// action à chaque membre de chaque groupe qui la porte.
//
// # Deux garde-fous
//
//   - Le groupe protégé n'est jamais soumis à un refus. Sans cela, un « deny »
//     posé sur `write:update:permission` d'une permission que portent tous les
//     administrateurs ne pourrait plus être levé par personne : le seul droit
//     qui permet de le retirer serait celui qu'il retire. Le groupe protégé
//     porte tous les droits par construction ; il doit pouvoir réparer.
//   - Poser ou lever un « deny » exige le droit GLOBAL (voir
//     core/action/actions_permission_grammaire.go). Un refus franchit les
//     domaines — il retire aussi ce qu'un autre groupe, ailleurs, accorde —,
//     donc il ne peut pas relever d'un délégué de domaine.

// ValeurRefus est la valeur d'action du refus explicite.
const ValeurRefus = "deny"

// Accès à la base, isolés pour que la RÈGLE s'éprouve sans base de données.
var (
	lireContenuPermission = func(groupID int, action string) (string, error) {
		return dbpermission.GetPermissionContent(database.GetDatabase(), groupID, action)
	}
	estExempteDesRefus = func(groupIDs []int) bool {
		return isprotected.GroupesContiennentLeGroupeProtege(database.GetDatabase(), groupIDs)
	}
)

// refusExplicite dit si l'un des groupes pose un « deny » sur l'action, et
// lequel.
//
// À appeler AVANT toute recherche d'accord : un refus explicite ne dépend ni du
// domaine ni de l'ordre des groupes. Le parcourir en même temps que les accords
// le ferait dépendre des deux — le premier groupe qui accorde arrêterait la
// boucle avant d'avoir vu le refus.
//
// Une erreur de lecture n'est PAS un refus : c'est l'absence d'information, et
// le groupe illisible n'accorde rien non plus dans la boucle des accords, qui
// le saute. Le contrôle reste fermé sans qu'une base hésitante transforme un
// incident en refus généralisé.
func refusExplicite(groupIDs []int, action string) (int, bool) {
	for _, groupID := range groupIDs {
		content, err := lireContenuPermission(groupID, action)
		if err != nil {
			continue
		}
		if ParsePermissionContent(strings.TrimSpace(content)).Refus {
			if estExempteDesRefus(groupIDs) {
				// Une ligne DEBUG et non WARNING : l'exemption est la règle,
				// pas une anomalie. Elle se cherche quand on se demande
				// pourquoi un administrateur passe malgré un refus.
				logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf(
					"droit %s : refus explicite du groupe %d ignoré (membre du groupe %s)",
					action, groupID, isprotected.ProtectedGroupName))
				return 0, false
			}
			return groupID, true
		}
	}
	return 0, false
}

// journaliserRefus écrit LA ligne d'un refus explicite.
//
// WARNING, comme les autres refus : c'est ce qu'on cherche dans un journal
// d'exploitation. Elle nomme le groupe qui refuse — devant un droit qui
// « devrait » passer parce qu'un autre groupe l'accorde, c'est la seule
// information qui explique.
func journaliserRefus(action string, groupID int, groupIDs []int) string {
	logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, fmt.Sprintf(
		"Action '%s' refusée : refus explicite (deny) posé par le groupe %d, "+
			"prioritaire sur les autres groupes %v", action, groupID, groupIDs))
	return fmt.Sprintf("refus explicite (deny) via le groupe %d", groupID)
}

// ContientUnRefus dit si l'une des valeurs brutes est un « deny ».
//
// Pour les chemins qui lisent les valeurs sans les groupes — la recherche
// LDAP.
func ContientUnRefus(valeurs []string) bool {
	for _, v := range valeurs {
		if strings.TrimSpace(v) == ValeurRefus {
			return true
		}
	}
	return false
}

// CompteExempteDesRefus dit si un compte échappe aux refus explicites : s'il
// est membre du groupe protégé. Pour les chemins qui raisonnent sur un nom.
//
// Un compte dont les groupes ne se lisent pas n'est pas exempté : dans le
// doute, le refus tient.
func CompteExempteDesRefus(username string) bool {
	groupIDs, err := GetGroupIDsForUser(username)
	if err != nil {
		return false
	}
	return estExempteDesRefus(groupIDs)
}

// MotifDeRefusExplicite rend le motif d'un refus explicite sur une action, et
// le journalise ; une chaîne vide s'il n'y en a pas.
//
// Pour les appelants qui n'ont reçu qu'un booléen — HasActionAnywhere — et
// doivent dire POURQUOI ils refusent. « Accordé sur aucun domaine » ferait
// chercher un domaine manquant, alors qu'un autre groupe accorde bel et bien :
// c'est le refus qui tranche, et c'est lui qu'il faut nommer.
func MotifDeRefusExplicite(groupIDs []int, action string) string {
	normalizedAction, ok := IsValidAction(action)
	if !ok {
		return ""
	}
	if groupID, refuse := refusExplicite(groupIDs, normalizedAction); refuse {
		return journaliserRefus(normalizedAction, groupID, groupIDs)
	}
	return ""
}
