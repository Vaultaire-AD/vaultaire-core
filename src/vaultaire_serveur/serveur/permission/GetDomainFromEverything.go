package permission

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/logs"
	"fmt"
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

func GetDomainslistFromUserpermission(permissionName string) ([]string, error) {
	domainsUser, err := db_permission.Command_GET_Domains_ByUserPermission(database.GetDatabase(), permissionName)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération des domaines pour la permission utilisateur "+permissionName+" : "+err.Error())
		return nil, err
	}
	return domainsUser, nil
}

func GetDomainslistFromClientpermission(permissionName string) ([]string, error) {
	domainsClient, err := db_permission.Command_GET_Domains_ByClientPermission(database.GetDatabase(), permissionName)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération des domaines pour la permission utilisateur "+permissionName+" : "+err.Error())
		return nil, err
	}
	return domainsClient, nil
}

func GetDomainslistFromGPO(gpoName string) ([]string, error) {
	domainsGPO, err := db_permission.GetDomainsByGPO(gpoName)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération des domaines pour la GPO "+gpoName+" : "+err.Error())
		return nil, err
	}
	return domainsGPO, nil
}

func GetDomainsFromGroupName(groupName string) ([]string, error) {
	domains, err := database.GetDomainsFromGroupName(groupName)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération des domaines pour le groupe "+groupName+" : "+err.Error())
		return nil, err
	}
	return domains, nil
}

// GetDomainsFromClientByComputerID retourne la liste de tous les domaines liés à un client via son ComputerID
func GetDomainsFromClientByComputerID(computerID string) ([]string, error) {
	db := database.GetDatabase()

	// Récupérer l'ID du client via le ComputerID
	clientID, err := database.Get_ClientID_By_ComputerID(db, computerID)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération clientID pour ComputerID "+fmt.Sprint(computerID)+" : "+err.Error())
		return nil, err
	}

	// Récupérer tous les groupes associés à ce client
	groupIDs, err := database.Command_GET_GroupIDsFromClientID(db, clientID)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération groupes pour le client "+fmt.Sprint(clientID)+" : "+err.Error())
		return nil, err
	}

	if len(groupIDs) == 0 {
		return nil, nil // aucun domaine si pas de groupe
	}

	// Récupérer tous les domaines liés aux groupes
	domains, err := database.Command_GET_DomainsFromGroupIDs(db, groupIDs)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération domaines pour les groupes du client "+fmt.Sprint(clientID)+" : "+err.Error())
		return nil, err
	}

	return domains, nil
}
