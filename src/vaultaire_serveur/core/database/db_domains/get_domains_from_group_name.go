package dbdomains

import (
	database "vaultaire/core/database"
	dbgroups "vaultaire/core/database/db_groups"
	"vaultaire/core/logs"
)

func GetDomainsFromGroupName(groupName string) ([]string, error) {
	db := database.GetDatabase()

	// On récupère l'ID du groupe via son nom
	groupID, err := dbgroups.GetGroupIDByName(db, groupName)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération ID du groupe "+groupName+" : "+err.Error())
		return nil, err
	}

	// On récupère les domaines associés à ce groupe
	domains, err := Command_GET_DomainsFromGroupIDs(db, []int{groupID})
	if err != nil {
		logs.Write_Log("WARNING", "Erreur récupération domaines du groupe "+groupName+" : "+err.Error())
		return nil, err
	}

	return domains, nil
}
