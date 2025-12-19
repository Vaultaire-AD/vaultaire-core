package database

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"database/sql"
	"fmt"
)

func Command_GET_AllClients(db *sql.DB) ([]storage.GetClientsByPermission, error) {
	// Requête SQL pour récupérer tous les clients
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
			id_logiciels l
	`

	// Exécution de la requête SQL
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

	// Déclaration d'une slice pour stocker les résultats
	var clients []storage.GetClientsByPermission
	for rows.Next() {
		// Structure pour stocker un client logiciel
		var client storage.GetClientsByPermission
		// Scan des résultats de la requête dans la structure
		if err := rows.Scan(&client.ID, &client.LogicielType, &client.ComputeurID, &client.Hostname, &client.Serveur, &client.Processeur, &client.RAM, &client.OS); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		// Ajout du client à la slice
		clients = append(clients, client)
	}

	// Vérifier s'il y a une erreur d'itération des résultats
	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	// Retourner les clients récupérés
	return clients, nil
}
