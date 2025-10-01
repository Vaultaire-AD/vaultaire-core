package permission

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"fmt"
)

func PrePermissionCheck(username, action string) ([]int, string, error) {
	// Placeholder for future pre-permission checks
	acUserID, err := database.Get_User_ID_By_Username(database.GetDatabase(), username)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la récupération de l'ID utilisateur pour %s : %v", username, err))
		return nil, "", fmt.Errorf("Erreur lors de la récupération de l'ID utilisateur.")
	}
	Domain_list, err := database.GetDomainsForUser(database.DB, acUserID)
	logs.Write_Log("DEBUG", fmt.Sprintf("Domaines pour l'utilisateur %s (ID %d) : %v", username, acUserID, Domain_list))
	action, CheckPermission := IsValidAction(action)
	if !CheckPermission {
		return nil, "", fmt.Errorf("Action non valide, contactez l'éditeur.")
	}
	groupsID, err := database.GetGroupIDsFromDomains(database.DB, Domain_list)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la récupération des groupes de l'utilisateur %s : %v", username, err))
		return nil, "", fmt.Errorf("Erreur lors de la récupération des groupes de l'utilisateur.")
	}

	return groupsID, action, nil
}
