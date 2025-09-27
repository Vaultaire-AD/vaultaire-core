package database

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"database/sql"
	"fmt"
)

func Command_GET_GroupDetails(db *sql.DB) ([]storage.GroupDetails, error) {
	query := `
	SELECT 
		g.group_name,
		dg.domain_name,
		COUNT(DISTINCT gp.d_id_permission) AS logiciel_permission_count,
		COUNT(DISTINCT gup.d_id_user_permission) AS user_permission_count,
		COUNT(DISTINCT ug.d_id_user) AS user_count,
		COUNT(DISTINCT lg.d_id_logiciel) AS client_count
	FROM 
		groups g
	LEFT JOIN 
		domain_group dg ON g.id_group = dg.d_id_group
	LEFT JOIN 
		group_permission_logiciel gp ON g.id_group = gp.d_id_group
	LEFT JOIN 
		group_user_permission gup ON g.id_group = gup.d_id_group
	LEFT JOIN 
		users_group ug ON g.id_group = ug.d_id_group
	LEFT JOIN 
		logiciel_group lg ON g.id_group = lg.d_id_group
	GROUP BY 
		g.id_group, dg.domain_name
`

	rows, err := db.Query(query)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var groupDetails []storage.GroupDetails

	for rows.Next() {
		var groupName, domainName string
		var logicielPermissionCount, userPermissionCount, userCount, clientCount int

		if err := rows.Scan(&groupName, &domainName, &logicielPermissionCount, &userPermissionCount, &userCount, &clientCount); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}

		groupDetails = append(groupDetails, storage.GroupDetails{
			GroupName:               groupName,
			DomainName:              domainName,
			LogicielPermissionCount: logicielPermissionCount,
			UserPermissionCount:     userPermissionCount,
			UserCount:               userCount,
			ClientCount:             clientCount,
		})
	}

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	return groupDetails, nil
}
