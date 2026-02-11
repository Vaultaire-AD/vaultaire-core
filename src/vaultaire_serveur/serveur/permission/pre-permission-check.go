package permission

import (
	"fmt"
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
)

// GetGroupIDsForUser retourne les IDs des groupes de l'utilisateur (via ses domaines).
// Utilisé par les commandes qui vérifient ensuite une action RBAC (catégorie:action:objet).
func GetGroupIDsForUser(username string) ([]int, error) {
	acUserID, err := database.Get_User_ID_By_Username(database.GetDatabase(), username)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur récupération ID utilisateur pour %s : %v", username, err))
		return nil, fmt.Errorf("erreur récupération utilisateur")
	}
	domainList, err := database.GetDomainsForUser(database.DB, acUserID)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur récupération domaines pour %s : %v", username, err))
		return nil, fmt.Errorf("erreur récupération domaines")
	}
	logs.Write_Log("INFO", fmt.Sprintf("Domaines pour %s (ID %d) : %v", username, acUserID, domainList))
	groupsID, err := database.GetGroupIDsFromDomains(database.DB, domainList)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur récupération groupes pour %s : %v", username, err))
		return nil, fmt.Errorf("erreur récupération groupes")
	}
	return groupsID, nil
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
