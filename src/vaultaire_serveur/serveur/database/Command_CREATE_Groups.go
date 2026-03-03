package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
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

func DeleteGroup(db *sql.DB, groupID int) error {
	tx, err := db.Begin()
	if err != nil {
		logs.WriteLog("db", "erreur lors de l'initialisation de la transaction DeleteGroup : "+err.Error())
		return fmt.Errorf("erreur lors de l'initialisation de la transaction: %v", err)
	}

	// Supprimer les liens avec les permissions
	_, err = tx.Exec(`DELETE FROM group_permission WHERE d_id_group = ?`, groupID)
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de la suppression des liens de permissions du groupe DeleteGroup : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression des liens de permissions du groupe: %v", err)
	}

	// Supprimer le groupe
	_, err = tx.Exec(`DELETE FROM groupe WHERE id_group = ?`, groupID)
	if err != nil {
		err = tx.Rollback()
		if err != nil {
			logs.WriteLog("db", "erreur lors de l'annulation de la transaction : "+err.Error())
		}
		logs.WriteLog("db", "erreur lors de la suppression du groupe DeleteGroupe: "+err.Error())
		return fmt.Errorf("erreur lors de la suppression du groupe: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la validation de la transaction DeleteGroup: "+err.Error())
		return fmt.Errorf("erreur lors de la validation de la transaction: %v", err)
	}

	return nil
}

func GetGroupIDByName(db *sql.DB, groupName string) (int, error) {
	var permissionID int

	err := db.QueryRow(`SELECT id_group FROM groups WHERE group_name = ?`, groupName).Scan(&permissionID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", fmt.Sprintf("permission '%s' introuvable", groupName))
			return 0, fmt.Errorf("permission '%s' introuvable", groupName)
		}
		logs.WriteLog("db", "erreur lors de la récupération de l'ID de la permission: "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID de la permission: %v", err)
	}

	return permissionID, nil
}
