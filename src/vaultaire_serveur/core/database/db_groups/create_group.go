package dbgroups

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

func CreateGroup(db *sql.DB, groupName string, domainName string) (int64, error) {

	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "erreur lors de l'initialisation de la transaction CreateGroupe: "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'initialisation de la transaction: %v", err)
	}

	// Insérer le groupe
	result, err := tx.Exec(`INSERT INTO groups (group_name) VALUES (?)`, groupName)
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de l'insertion du groupe CreateGroupe: "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion du groupe: %v", err)
	}

	groupID, err := result.LastInsertId()
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de la récupération de l'ID du groupe CreateGroupe: "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID du groupe: %v", err)
	}
	// Insérer le domaine associé
	_, err = tx.Exec(`INSERT INTO domain_group (d_id_group, domain_name) VALUES (?, ?)`, groupID, domainName)
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de l'insertion du domaine CreateGroup: "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion du domaine: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la validation de la transaction CreateGroupe : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la validation de la transaction: %v", err)
	}

	return groupID, nil
}
