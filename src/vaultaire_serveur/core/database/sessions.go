package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func AddLoginEntry(db *sql.DB, userID int, sessionPublicKey []byte, clientSoftwareID string) {
	sessionVal := time.Now().Add(10 * time.Minute)
	formattedTime := sessionVal.Format("2006/01/02 15:04:05")

	// La machine est résolue par le helper commun, et l'échec ARRÊTE la
	// fonction.
	//
	// get_id_logiciel, qui vivait ici, retournait une chaîne vide aussi bien
	// pour « machine inconnue » que pour « erreur de base ». Cette chaîne vide
	// partait ensuite dans un INSERT sur d_id_logiciel, une clé étrangère
	// entière : l'insertion échouait, l'échec n'était que journalisé, et
	// AddLoginEntry — qui ne retourne rien — laissait l'appelant croire la
	// session enregistrée. Une connexion réussie sans ligne did_login
	// correspondante, c'est une session que le nettoyage et le kill switch ne
	// retrouveront jamais.
	//
	// Continuer sans identifiant valide n'a aucun sens : on s'arrête, et on le
	// dit franchement dans le journal.
	logiciel_id, err := Get_ClientID_By_ComputerID(db, clientSoftwareID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: session non enregistrée, machine "+clientSoftwareID+" introuvable : "+err.Error())
		return
	}

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la création de la transaction :"+err.Error())
	}

	var exists bool
	err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM did_login WHERE d_id_user = ? AND d_id_logiciel = ?)", userID, logiciel_id).Scan(&exists)
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de la vérification de l'existence de l'entrée did_login : "+err.Error())
	}

	if exists {
		_, err = tx.Exec(`
        UPDATE did_login
        SET session_key = ?, key_time_validity = ?
        WHERE d_id_user = ? AND d_id_logiciel = ?
    `, sessionPublicKey, formattedTime, userID, logiciel_id)
		if err != nil {
			err = tx.Rollback()
			if err != nil {
				logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
			}
			logs.WriteLog("db", "erreur lors de la mise à jour de l'entrée de connexion : "+err.Error())
		}
	} else {
		_, err = tx.Exec(`
        INSERT INTO did_login (d_id_user, session_key, key_time_validity, d_id_logiciel)
        VALUES (?, ?, ?, ?)
    `, userID, sessionPublicKey, formattedTime, logiciel_id)
		if err != nil {
			err = tx.Rollback()
			if err != nil {
				logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
			}
			logs.WriteLog("db", "erreur lors de l'insertion de l'entrée de connexion : "+err.Error())
		}
	}
	err = tx.Commit()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la validation de la transaction : "+err.Error())
	}

	tx, err = db.Begin()
	if err != nil {
		logs.WriteLog("db", "failed to begin transaction:: "+err.Error())
	}
	// defer tx.Rollback()

	checkQuery := `
		SELECT EXISTS (
			SELECT 1 FROM users_logiciel WHERE d_id_user = ? AND d_id_logiciel = ?
		)
	`

	err = tx.QueryRow(checkQuery, userID, logiciel_id).Scan(&exists)
	if err != nil {
		logs.WriteLog("db", "failed to check existing entry: "+err.Error())
	}

	if exists {
		// Mise à jour de recent_utilisation
		updateQuery := `
			UPDATE users_logiciel
			SET recent_utilisation = ?
			WHERE d_id_user = ? AND d_id_logiciel = ?
		`
		_, err = tx.Exec(updateQuery, formattedTime, userID, logiciel_id)
		if err != nil {
			logs.WriteLog("db", "failed to update entry:: "+err.Error())
		}
	} else {
		// Insérer une nouvelle ligne
		insertQuery := `
			INSERT INTO users_logiciel (d_id_user, d_id_logiciel, recent_utilisation)
			VALUES (?, ?, ?)
		`
		_, err = tx.Exec(insertQuery, userID, logiciel_id, formattedTime)
		if err != nil {
			logs.WriteLog("db", "failed to insert new user: "+err.Error())
		}
	}

	// Valider la transaction
	err = tx.Commit()
	if err != nil {
		logs.WriteLog("db", "failed to commit transaction: "+err.Error())
	}
}

// get_id_logiciel a été retirée au profit de Get_ClientID_By_ComputerID.
//
// Elle posait la même requête, mais avec trois défauts que le helper n'a pas :
// pas de sanitisation de l'entrée, une chaîne vide indistinctement retournée
// pour « introuvable » et pour « erreur de base », et une variable de retour
// nommée `publicKey` alors qu'elle contient un identifiant.

func RefreshSessionValidity(db *sql.DB, sessionKey []byte) error {

	expiration := time.Now().Add(10 * time.Minute)
	formattedTime := expiration.Format("2006/01/02 15:04:05")

	query := `
		UPDATE did_login
		SET key_time_validity = ?
		WHERE session_key = ?
	`

	_, err := db.Exec(
		query,
		formattedTime,
		sessionKey,
	)

	return err
}

// CleanUpExpiredSessions supprime les entrées did_login dont key_time_validity
// est dépassé.
//
// La comparaison se fait entièrement côté SQL (WHERE key_time_validity <
// NOW()) plutôt qu'en récupérant la date en Go pour la reparser : le driver
// MySQL (DSN parseTime=true) renvoie un TIMESTAMP scanné dans un string sous
// forme RFC3339Nano (ex "2026-07-28T15:43:41Z"), alors que le code
// attendait un format "2006-01-02 15:04:05" — ça ne matchait jamais et
// faisait échouer le nettoyage à chaque tick, en boucle, sans jamais rien
// supprimer. Laisser MySQL faire la comparaison de dates élimine ce problème
// de format une fois pour toutes.
func CleanUpExpiredSessions(db *sql.DB) error {
	rows, err := db.Query("SELECT d_id_user FROM did_login WHERE key_time_validity < NOW()")
	if err != nil {
		return fmt.Errorf("erreur lors de la lecture des sessions expirées : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var expiredUserIDs []int
	for rows.Next() {
		var userID int
		if err := rows.Scan(&userID); err != nil {
			return fmt.Errorf("erreur lors de l'extraction des données : %v", err)
		}
		expiredUserIDs = append(expiredUserIDs, userID)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("erreur lors de la lecture des sessions expirées : %v", err)
	}

	// Supprimer les sessions expirées
	for _, userID := range expiredUserIDs {
		_, err := db.Exec("DELETE FROM did_login WHERE d_id_user = ?", userID)
		if err != nil {
			return fmt.Errorf("erreur lors de la suppression des sessions expirées : %v", err)
		}
		logs.Write_Log("INFO", fmt.Sprintf("Session expirée pour user_id %d supprimée", userID))
	}

	return nil
}

func DeleteDidLogin(db *sql.DB, Username string, computeurID string) error {
	injection := SanitizeIdentifier(computeurID, Username)
	if injection != nil {
		return injection
	}
	// Les deux identifiants passent par les helpers dédiés, et leurs erreurs
	// sont remontées.
	//
	// Elles étaient ignorées — `idUser, _ :=` — ce qui envoyait un 0 dans le
	// DELETE quand le compte ou la machine n'existait plus. La requête ne
	// supprimait alors rien, la fonction retournait nil, et l'appelant croyait
	// la ligne de connexion nettoyée. Le seul indice était un log « Aucune ligne
	// supprimée » noyé dans la sortie standard.
	//
	// Get_ClientID_By_ComputerID remplace GetIdLogicielByComputeurID, qui posait
	// exactement la même requête pour retourner la même colonne en `string` au
	// lieu d'`int`. Deux fonctions pour une question, avec deux types : c'est ce
	// qui obligeait le reste du code à convertir dans un sens ou dans l'autre
	// selon l'endroit.
	idUser, err := Get_User_ID_By_Username(db, Username)
	if err != nil {
		return fmt.Errorf("suppression de la session : utilisateur %s introuvable : %w", Username, err)
	}
	idLogiciel, err := Get_ClientID_By_ComputerID(db, computeurID)
	if err != nil {
		return fmt.Errorf("suppression de la session : machine %s introuvable : %w", computeurID, err)
	}

	query := "DELETE FROM did_login WHERE d_id_user = ? AND d_id_logiciel = ?"
	stmt, err := db.Prepare(query)
	if err != nil {
		return fmt.Errorf("erreur de préparation de la requête : %w", err)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	result, err := stmt.Exec(idUser, idLogiciel)
	if err != nil {
		return fmt.Errorf("erreur lors de l'exécution de la requête : %w", err)
	}

	raffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("erreur lors de la récupération des lignes affectées : %w", err)
	}

	if raffected == 0 {
		log.Println("Aucune ligne supprimée, vérifiez les valeurs de id_user et id_logiciel")
	} else {
		log.Printf("%d ligne(s) supprimée(s)\n", raffected)
	}

	return nil
}

// GetConnectedUsers récupère les utilisateurs connectés
func Command_STATUS_GetConnectedUsers(db *sql.DB) ([]storage.UserConnected, error) {
	query := `
		SELECT 
			users.id_user, 
			users.username, 
			users.created_at, 
			did_login.key_time_validity
		FROM 
			did_login
		INNER JOIN 
			users 
		ON 
			did_login.d_id_user = users.id_user
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var connectedUsers []storage.UserConnected
	for rows.Next() {
		var user storage.UserConnected
		err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt, &user.TokenExpiry)
		if err != nil {
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		connectedUsers = append(connectedUsers, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	return connectedUsers, nil
}

func Command_STATUS_GetConnectedUser(db *sql.DB, username string) ([]storage.UserConnected, error) {
	query := `
		SELECT 
			users.id_user, 
			users.username, 
			users.created_at, 
			did_login.key_time_validity
		FROM 
			did_login
		INNER JOIN 
			users 
		ON 
			did_login.d_id_user = users.id_user
		WHERE
			users.username = ?
	`

	rows, err := db.Query(query, username)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("db : Le user '%s' n'existe pas.", username)
			return nil, fmt.Errorf("le user '%s' n'existe pas", username)
		}
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var connectedUsers []storage.UserConnected
	for rows.Next() {
		var user storage.UserConnected
		err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt, &user.TokenExpiry)
		if err != nil {
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		connectedUsers = append(connectedUsers, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	return connectedUsers, nil
}

func Command_STATUS_GetClientsConnected(db *sql.DB) ([]storage.ClientConnected, error) {
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
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Aucun client connecté trouvé")
		return nil, fmt.Errorf("aucun client connecté trouvé")
	}

	return clients, nil
}

func Command_STATUS_GetClientsConnectedByGroup(db *sql.DB, groupName string) ([]storage.ClientConnected, error) {
	injection := SanitizeIdentifier(groupName)
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
		INNER JOIN logiciel_group ON id_logiciels.id_logiciel = logiciel_group.d_id_logiciel
		INNER JOIN groups ON logiciel_group.d_id_group = groups.id_group
		WHERE groups.group_name = ?
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
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Aucun client connecté trouvé pour le groupe "+groupName)
		return nil, fmt.Errorf("aucun client connecté trouvé pour le groupe '%s'", groupName)
	}

	return clients, nil
}

func Command_STATUS_GetClientsConnectedByLogicielType(db *sql.DB, logicielType string) ([]storage.ClientConnected, error) {
	injection := SanitizeIdentifier(logicielType)
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
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Aucun client connecté trouvé pour le type de logiciel "+logicielType)
		return nil, fmt.Errorf("aucun client connecté trouvé pour le type de logiciel '%s'", logicielType)
	}

	return clients, nil
}

// Command_STATUS_GetUsersByGroup récupère les utilisateurs appartenant à un groupe spécifié.
func Command_STATUS_GetUsersByGroup(db *sql.DB, groupName string) ([]storage.UserConnected, error) {
	injection := SanitizeIdentifier(groupName)
	if injection != nil {
		return nil, injection
	}
	query := `
		SELECT 
			users.id_user, 
			users.username, 
			users.created_at, 
			did_login.key_time_validity
		FROM 
			users_group
		INNER JOIN users ON users_group.d_id_user = users.id_user
		LEFT JOIN did_login ON did_login.d_id_user = users.id_user
		INNER JOIN groups ON users_group.d_id_group = groups.id_group
		WHERE groups.group_name = ?
	`

	rows, err := db.Query(query, groupName)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: Le groupe "+groupName+" n'existe pas.")
			return nil, fmt.Errorf("le groupe '%s' n'existe pas", groupName)
		}
		logs.WriteLog("db", "Erreur lors de l'exécution de la requête : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'exécution de la requête : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var users []storage.UserConnected
	for rows.Next() {
		var user storage.UserConnected
		if err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt, &user.TokenExpiry); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des résultats : "+err.Error())
			return nil, fmt.Errorf("erreur lors du scan des résultats : %v", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		logs.WriteLog("db", "Erreur lors de l'itération des résultats : "+err.Error())
		return nil, fmt.Errorf("erreur lors de l'itération des résultats : %v", err)
	}

	if len(users) == 0 {
		logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Aucun utilisateur trouvé pour le groupe "+groupName)
		return nil, fmt.Errorf("aucun utilisateur trouvé pour le groupe '%s'", groupName)
	}

	return users, nil
}
