package permission

import (
	"fmt"
	"vaultaire/core/database"
	dbgroups "vaultaire/core/database/db_groups"
	"vaultaire/core/logs"
)

// GetGroupIDsForUser retourne les IDs des groupes DONT L'UTILISATEUR EST MEMBRE.
//
// C'est le point de passage de toute l'évaluation RBAC : routeur CLI (donc aussi
// l'API signée), requireWebAdminWithGroupIDs (donc toute l'interface web) et
// PrePermissionCheck (web_admin, auth LDAP). Les groupes retournés ici sont
// ceux dont les permissions seront évaluées.
//
// CORRECTION D'UNE ÉLÉVATION DE PRIVILÈGES. La version précédente enchaînait
// deux requêtes :
//
//	GetDomainsForUser      -> les domaines des groupes de l'utilisateur
//	GetGroupIDsFromDomains -> TOUS les groupes de ces domaines
//
// L'aller-retour groupe → domaine → groupe ne revenait pas au point de départ,
// il élargissait. Un utilisateur membre du seul groupe « stagiaires » dans
// compta.example.fr était évalué avec les permissions de tous les groupes du
// domaine, « compta-admins » compris. Il suffisait qu'un seul groupe d'un
// domaine porte une permission forte pour que tous les comptes du domaine
// l'obtiennent : l'appartenance à un groupe ne servait plus à rien pour le
// RBAC, seul le domaine comptait.
//
// La lecture est donc désormais stricte : seuls les groupes dont l'utilisateur
// est réellement membre (table users_group). Le découpage par domaine reste
// entier — il vit dans la VALEUR des permissions, pas dans le choix des
// groupes évalués.
//
// Conséquence au déploiement : des comptes perdent des droits qu'ils avaient
// par effet de bord. Voir docs/Developement/migrations/ pour la requête qui
// liste les comptes concernés avant bascule.
func GetGroupIDsForUser(username string) ([]int, error) {
	// KILL SWITCH — point de coupure unique.
	//
	// Un compte révoqué n'a aucun groupe, donc aucune permission, sur TOUS les
	// chemins d'un coup : CLI, API signée, interface web, LDAP. Le poser ici
	// plutôt que dans chaque commande garantit que rien n'est oublié — y
	// compris les commandes qui seront écrites plus tard.
	//
	// C'est un doublon volontaire des refus posés aux points
	// d'authentification : ceux-là coupent avant d'évaluer un mot de passe et
	// donnent un journal lisible, celui-ci rattrape toute session déjà ouverte
	// au moment de la révocation.
	if revokedChecker != nil && revokedChecker(username) {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"Accès refusé : le compte %s est révoqué (aucune permission accordée)", username))
		return nil, fmt.Errorf("compte révoqué")
	}

	groupsID, err := dbgroups.Command_GET_UserGroupIDs(database.GetDatabase(), username)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur récupération groupes pour %s : %v", username, err))
		return nil, fmt.Errorf("erreur récupération groupes")
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone,
		fmt.Sprintf("Groupes de %s (appartenance directe) : %v", username, groupsID))
	return groupsID, nil
}

// revokedChecker dit si un compte est révoqué.
//
// Injecté plutôt qu'importé. Un import direct de core/database/db_revocation
// compilerait — vérifié, il n'y a pas de cycle — mais il inverserait les
// couches : core/permission décide de la politique d'accès et n'a pas à
// connaître le schéma de stockage d'une fonctionnalité particulière. Le jour où
// la révocation change de support, c'est main qui s'adapte, pas le moteur RBAC.
//
// Même mécanisme que le RestrictionProvider des GPO, et pour la même raison.
var revokedChecker func(username string) bool

// SetRevokedChecker enregistre la fonction de vérification des révocations.
// Appelée une fois au démarrage, depuis main.
func SetRevokedChecker(f func(username string) bool) { revokedChecker = f }

// IsRevoked expose la vérification aux points d'authentification.
//
// Retourne false si aucun vérificateur n'a été enregistré — cas du démarrage
// avant l'initialisation de la base, où aucune authentification n'est encore
// possible de toute façon.
func IsRevoked(username string) bool {
	if revokedChecker == nil {
		return false
	}
	return revokedChecker(username)
}

// PrePermissionCheck retourne les groupIDs et l'action normalisée (pour web_admin, auth, etc.).
func PrePermissionCheck(username, action string) ([]int, string, error) {
	groupsID, err := GetGroupIDsForUser(username)
	if err != nil {
		return nil, "", err
	}
	action, ok := IsValidAction(action)
	if !ok {
		return nil, "", fmt.Errorf("action non valide")
	}
	return groupsID, action, nil
}
