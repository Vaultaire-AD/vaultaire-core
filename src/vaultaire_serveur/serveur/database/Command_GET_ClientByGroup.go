package database

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"database/sql"
	"fmt"
)

func Command_GET_ClientsByGroup(db *sql.DB, groupName string) ([]storage.GetClientsByGroup, error) {
	injection := SanitizeInput(groupName)
	if injection != nil {
		return nil, injection
	}
	query := `
		SELECT 
			l.id_logiciel, 
			l.logiciel_type, 
			l.computeur_id, 
			l.hostname, 
			l.serveur, 
			l.processeur, 
			l.ram, 
			l.os 
		FROM 
			logiciel_group lg
		JOIN 
			id_logiciels l ON lg.d_id_logiciel = l.id_logiciel
		JOIN 
			groups g ON lg.d_id_group = g.id_group
		WHERE 
			g.group_name = ?
	`

	rows, err := db.Query(query, groupName)
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

	var clients []storage.GetClientsByGroup
	for rows.Next() {
		var client storage.GetClientsByGroup
		if err := rows.Scan(&client.ID, &client.LogicielType, &client.ComputeurID, &client.Hostname, &client.Serveur, &client.Processeur, &client.RAM, &client.OS); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		clients = append(clients, client)
	}

	// Vérifier s'il y a une erreur d'itération des résultats
	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	return clients, nil
}
