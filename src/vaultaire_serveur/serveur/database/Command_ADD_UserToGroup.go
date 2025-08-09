package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

func Command_ADD_UserToGroup(db *sql.DB, username, groupName string) error {
	injection := SanitizeInput(username, groupName)
	if injection != nil {
		return injection
	}
	// Vérifier si l'utilisateur existe
	var userID int
	queryUser := `SELECT id_user FROM users WHERE username = ?`
	err := db.QueryRow(queryUser, username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("utilisateur avec le nom d'utilisateur %s introuvable", username)
		}
		logs.WriteLog("db", "Erreur lors de la récupération de l'utilisateur : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de l'utilisateur : %v", err)
	}

	// Vérifier si le groupe existe
	var groupID int
	queryGroup := `SELECT id_group FROM groups WHERE group_name = ?`
	err = db.QueryRow(queryGroup, groupName).Scan(&groupID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("groupe avec le nom %s introuvable", groupName)
		}
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}

	// Vérifier si l'utilisateur est déjà dans ce groupe
	var count int
	queryCheck := `SELECT COUNT(*) FROM users_group WHERE d_id_user = ? AND d_id_group = ?`
	err = db.QueryRow(queryCheck, userID, groupID).Scan(&count)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification de l'utilisateur dans le groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification de l'utilisateur dans le groupe : %v", err)
	}

	// Si l'utilisateur est déjà dans ce groupe, on ne fait rien
	if count > 0 {
		return fmt.Errorf("l'utilisateur %s est déjà membre du groupe %s", username, groupName)
	}

	// Ajouter l'utilisateur au groupe
	queryAdd := `INSERT INTO users_group (d_id_user, d_id_group) VALUES (?, ?)`
	_, err = db.Exec(queryAdd, userID, groupID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de l'ajout de l'utilisateur au groupe : "+err.Error())
		return fmt.Errorf("erreur lors de l'ajout de l'utilisateur au groupe : %v", err)
	}

	return nil
}
