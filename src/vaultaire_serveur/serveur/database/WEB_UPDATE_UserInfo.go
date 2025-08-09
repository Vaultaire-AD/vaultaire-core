package database

import (
	"DUCKY/serveur/logs"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// Fonction pour générer un salt aléatoire
func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}

func Update_User_Info(db *sql.DB, userID int, username, firstname, lastname, password, birthdate string) error {
	injection := SanitizeInput(username, password, birthdate)
	if injection != nil {
		return injection
	}

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "Erreur début transaction update: "+err.Error())
		return fmt.Errorf("erreur début transaction: %v", err)
	}
	defer tx.Rollback()

	// Récupérer domaine principal depuis les groupes de l'utilisateur
	mainDomain, err := GetUserMainDomain(db, userID)
	if err != nil {
		logs.WriteLog("db", "Erreur récupération domaine principal: "+err.Error())
		return fmt.Errorf("erreur récupération domaine principal: %v", err)
	}

	email := fmt.Sprintf("%s@%s", username, mainDomain)

	var (
		hashHex string
		saltHex string
	)

	if password != "" {
		salt, err := generateSalt(16)
		if err != nil {
			logs.WriteLog("auth", "Erreur génération salt: "+err.Error())
			return fmt.Errorf("erreur génération salt: %v", err)
		}
		saltHex = hex.EncodeToString(salt)

		saltedPassword := append(salt, []byte(password)...)
		hash := sha256.Sum256(saltedPassword)
		hashHex = hex.EncodeToString(hash[:])
	}

	if password != "" {
		_, err = tx.Exec(`
		UPDATE users
		SET username = ?, firstname = ?, lastname = ?, email = ?, password = ?, salt = ?
		WHERE id_user = ?`,
			username, firstname, lastname, email, hashHex, saltHex, userID)
	} else {
		_, err = tx.Exec(`
		UPDATE users
		SET username = ?, firstname = ?, lastname = ?, email = ?
		WHERE id_user = ?`,
			username, firstname, lastname, email, userID)
	}

	if err != nil {
		logs.WriteLog("db", "Erreur update user: "+err.Error())
		return fmt.Errorf("erreur update: %v", err)
	}

	if err = tx.Commit(); err != nil {
		logs.WriteLog("db", "Erreur commit update: "+err.Error())
		return fmt.Errorf("erreur commit: %v", err)
	}

	return nil
}
