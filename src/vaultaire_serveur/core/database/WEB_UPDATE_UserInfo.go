package database

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"vaultaire/core/logs"
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

	// Le compte d'amorçage ne peut pas être renommé (son nom est câblé dans
	// l'authentification serveur et le bind LDAP). Le changement de mot de passe
	// reste autorisé : le compte naît avec un mot de passe par défaut connu,
	// bloquer sa rotation serait contre-productif. Voir protected.go.
	var currentUsername string
	if err := db.QueryRow(`SELECT username FROM users WHERE id_user = ?`, userID).Scan(&currentUsername); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("utilisateur %d introuvable", userID)
		}
		logs.WriteLog("db", "Erreur lecture username courant: "+err.Error())
		return fmt.Errorf("erreur lecture de l'utilisateur %d: %v", userID, err)
	}
	if err := GuardProtectedUserRename(currentUsername, username); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "Erreur début transaction update: "+err.Error())
		return fmt.Errorf("erreur début transaction: %v", err)
	}
	defer func() {
		if rerr := tx.Rollback(); rerr != nil && rerr != sql.ErrTxDone {
			// Log rollback failure (don't usually return it, because the main err is more important)
			logs.WriteLog("db", "Erreur rollback transaction update: "+rerr.Error())
		}
	}()

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
