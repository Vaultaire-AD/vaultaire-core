package database

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
	"vaultaire/core/tools"

	_ "github.com/go-sql-driver/mysql"
)

func Create_New_User(db *sql.DB, username, firstname, lastname, email, password, salt, birthdate, createdAt string) error {
	// Le nom d'utilisateur nomme une entité : liste blanche. Le mot de passe est
	// du texte libre et doit le rester — y interdire espaces et parenthèses
	// affaiblirait les mots de passe au lieu de protéger la base.
	if err := SanitizeIdentifier(username); err != nil {
		return err
	}
	injection := SanitizeInput(password, birthdate)
	if injection != nil {
		return injection
	}

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "erreur lors du début de la transaction: "+err.Error())
		return fmt.Errorf("erreur lors du début de la transaction: %v", err)
	}

	defer func() {
		if rerr := tx.Rollback(); rerr != nil && rerr != sql.ErrTxDone {
			// Log rollback failure (don't usually return it, because the main err is more important)
			logs.WriteLog("db", "erreur lors du rollback de la transaction: "+rerr.Error())
		}
	}()

	birthdate, err = tools.StringToDate(birthdate)
	if err != nil {
		logs.WriteLog("date", "Date de naissance invalide: "+err.Error())
		return fmt.Errorf("format de date invalide: %v", err)
	}
	// 1. Insérer un nouvel utilisateur dans la table users
	//
	// password_changed_at est posé dès la création, et non laissé à NULL.
	// Le rattrapage du schéma (db_authpolicy) ne s'exécute qu'au démarrage : un
	// compte créé ensuite garderait une date nulle jusqu'au prochain
	// redémarrage, donc un mot de passe qui n'expire jamais. Le trou serait
	// invisible — le compte fonctionne — et ne se refermerait qu'au hasard des
	// redémarrages.
	_, err = tx.Exec(`
		INSERT INTO users (username, firstname, lastname, email, password, salt, date_naissance, created_at, password_changed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, username, firstname, lastname, email, password, salt, birthdate, createdAt, createdAt)
	if err != nil {
		logs.WriteLog("db", "erreur lors de l'insertion de l'utilisateur: "+err.Error())
		return fmt.Errorf("erreur lors de l'insertion de l'utilisateur: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la validation de la transaction: "+err.Error())
		return fmt.Errorf("erreur lors de la validation de la transaction: %v", err)
	}

	return nil
}
