package permission

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func GetDomainListFromUsername(username string) ([]string, error) {
	userID, err := database.Get_User_ID_By_Username(database.GetDatabase(), username)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération de l'ID utilisateur pour "+username+" : "+err.Error())
		return nil, err
	}

	domainList, err := database.GetDomainsForUser(database.DB, userID)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération des domaines pour l'utilisateur "+username+" : "+err.Error())
		return nil, err
	}

	// Si aucun domaine trouvé, on retourne un wildcard
	if len(domainList) == 0 {
		domainList = []string{"*"}
	}

	return domainList, nil
}

// GetGroupIDsFromUsername retourne la liste des IDs de groupes pour un utilisateur
func GetGroupIDsFromUsername(username string) ([]int, error) {
	groupIDs, err := database.Command_GET_UserGroupIDs(database.GetDatabase(), username)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération des groupes de l'utilisateur "+username+" : "+err.Error())
		return nil, err
	}
	return groupIDs, nil
}

// GetDomainListsFromGroupIDs retourne la liste des domaines pour une liste d'IDs de groupes
func GetDomainListsFromGroupIDs(groupIDs []int) ([]string, error) {
	domainList, err := database.Command_GET_DomainsFromGroupIDs(database.GetDatabase(), groupIDs)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération des domaines pour les groupes : "+err.Error())
		return nil, err
	}
	return domainList, nil
}
