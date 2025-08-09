package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"time"
)

func AddLoginEntry(db *sql.DB, userID int, sessionPublicKey []byte, clientSoftwareID string) {
	sessionVal := time.Now().Add(1 * time.Hour)
	formattedTime := sessionVal.Format("2006/01/02 15:04:05")
	logiciel_id := get_id_logiciel(db, clientSoftwareID)

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la création de la transaction :"+err.Error())
	}

	var exists bool
	err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM did_login WHERE d_id_user = ? AND d_id_logiciel = ?)", userID, logiciel_id).Scan(&exists)
	if err != nil {
		tx.Rollback()
		logs.WriteLog("db", "erreur lors de la vérification de l'existence de l'entrée did_login : "+err.Error())
	}

	if exists {
		_, err = tx.Exec(`
        UPDATE did_login
        SET session_key = ?, key_time_validity = ?
        WHERE d_id_user = ? AND d_id_logiciel = ?
    `, sessionPublicKey, formattedTime, userID, logiciel_id)
		if err != nil {
			tx.Rollback()
			logs.WriteLog("db", "erreur lors de la mise à jour de l'entrée de connexion : "+err.Error())
		}
	} else {
		_, err = tx.Exec(`
        INSERT INTO did_login (d_id_user, session_key, key_time_validity, d_id_logiciel)
        VALUES (?, ?, ?, ?)
    `, userID, sessionPublicKey, formattedTime, logiciel_id)
		if err != nil {
			tx.Rollback()
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
	defer tx.Rollback()

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

func get_id_logiciel(db *sql.DB, logiciel_id string) string {
	var publicKey string
	query := `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ?`

	err := db.QueryRow(query, logiciel_id).Scan(&publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "clé publique non trouvée pour l'utilisateur ID"+err.Error())
			return ""
		}
		logs.WriteLog("db", "erreur lors de la récupération de la clé publique: "+err.Error())
		return ""
	}

	return publicKey
}
