package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

// Vérifie si un utilisateur peut se connecter avec un client (partage un groupe ou une permission)
func DidUserCanLogin(db *sql.DB, username, computeur_id string) (bool, error) {
	injection := SanitizeInput(username, computeur_id)
	if injection != nil {
		return false, injection
	}
	var userID int
	// Récupère l'ID de l'utilisateur basé sur le username
	query := `SELECT id_user FROM users WHERE username = ?`
	err := db.QueryRow(query, username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "Utilisateur non trouvé: "+username)
			return false, fmt.Errorf("utilisateur non trouvé")
		}
		logs.WriteLog("db", "Erreur lors de la récupération de l'ID utilisateur: "+err.Error())
		return false, err
	}

	// Vérification si l'utilisateur et l'ordinateur partagent un groupe via `users_group` et `logiciel_group`
	var canLogin bool
	query = `SELECT 1 FROM users_group 
			 JOIN logiciel_group ON users_group.d_id_group = logiciel_group.d_id_group
			 JOIN id_logiciels ON logiciel_group.d_id_logiciel = id_logiciels.id_logiciel
			 WHERE users_group.d_id_user = ? AND id_logiciels.computeur_id = ? LIMIT 1`
	err = db.QueryRow(query, userID, computeur_id).Scan(&canLogin)
	if err == nil && canLogin {
		logs.WriteLog("db", "Utilisateur "+username+" peut se connecter grâce à un groupe partagé.")
		return true, nil
	} else if err != sql.ErrNoRows {
		logs.WriteLog("db", "Erreur lors de la vérification du groupe partagé: "+err.Error())
		return false, err
	}

	// Si aucune correspondance n'est trouvée
	logs.WriteLog("db", "L'utilisateur "+username+" ne peut pas se connecter avec ce client "+computeur_id)
	return false, nil
}
