package database

import (
	"database/sql"
	"time"
	"vaultaire/core/logs"
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
