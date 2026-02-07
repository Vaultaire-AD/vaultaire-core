package database

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"database/sql"
	"fmt"
)

func Command_STATUS_GetClientsConnectedByLogicielType(db *sql.DB, logicielType string) ([]storage.ClientConnected, error) {
	injection := SanitizeInput(logicielType)
	if injection != nil {
		return nil, injection
	}
	query := `
		SELECT 
			users.username,
			id_logiciels.logiciel_type, 
			id_logiciels.computeur_id, 
			id_logiciels.hostname, 
			id_logiciels.serveur, 
			id_logiciels.processeur, 
			id_logiciels.ram, 
			id_logiciels.os
		FROM 
			did_login
		INNER JOIN id_logiciels ON did_login.d_id_logiciel = id_logiciels.id_logiciel
		INNER JOIN users ON did_login.d_id_user = users.id_user
		WHERE id_logiciels.logiciel_type = ?
	`

	rows, err := db.Query(query, logicielType)
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

	var clients []storage.ClientConnected
	for rows.Next() {
		var client storage.ClientConnected
		if err := rows.Scan(&client.Username, &client.LogicielType, &client.ComputeurID, &client.Hostname, &client.Serveur, &client.Processeur, &client.RAM, &client.OS); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	if len(clients) == 0 {
		logs.WriteLog("db", "Aucun client connecté trouvé pour le type de logiciel "+logicielType)
		return nil, fmt.Errorf("aucun client connecté trouvé pour le type de logiciel '%s'", logicielType)
	}

	return clients, nil
}
