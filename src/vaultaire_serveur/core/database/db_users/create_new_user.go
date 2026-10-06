package dbusers

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/identifiant"
	"vaultaire/core/logs"
	"vaultaire/core/tools"
)

func Create_New_User(db *sql.DB, username, firstname, lastname, email, password, salt, birthdate, createdAt string) error {
	// Le nom d'utilisateur nomme une entité : liste blanche. Le mot de passe est
	// du texte libre et doit le rester — y interdire espaces et parenthèses
	// affaiblirait les mots de passe au lieu de protéger la base.
	if err := database.SanitizeIdentifier(username); err != nil {
		return err
	}
	injection := database.SanitizeInput(password, birthdate)
	if injection != nil {
		return injection
	}

	tx, err := db.Begin()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors du début de la transaction: "+err.Error())
		return fmt.Errorf("erreur lors du début de la transaction: %v", err)
	}

	defer func() {
		if rerr := tx.Rollback(); rerr != nil && rerr != sql.ErrTxDone {
			// Log rollback failure (don't usually return it, because the main err is more important)
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors du rollback de la transaction: "+rerr.Error())
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
	//
	// entry_uuid est posé ICI, à la création, et jamais réécrit : c'est
	// l'identifiant sous lequel les clients LDAP reconnaissent le compte, y
	// compris après un renommage (point 129). Le rattrapage du schéma en
	// donnerait bien un au prochain démarrage — mais d'ici là le compte serait
	// servi sans identifiant, et un client qui l'importe dans l'intervalle ne
	// le reconnaîtrait plus ensuite.
	entryUUID, err := identifiant.NouvelUUID()
	if err != nil {
		return fmt.Errorf("identifiant du compte : %v", err)
	}
	_, err = tx.Exec(`
		INSERT INTO users (username, firstname, lastname, email, password, salt, date_naissance, created_at, password_changed_at, entry_uuid)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, username, firstname, lastname, email, password, salt, birthdate, createdAt, createdAt, entryUUID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors de l'insertion de l'utilisateur: "+err.Error())
		return fmt.Errorf("erreur lors de l'insertion de l'utilisateur: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors de la validation de la transaction: "+err.Error())
		return fmt.Errorf("erreur lors de la validation de la transaction: %v", err)
	}

	return nil
}
