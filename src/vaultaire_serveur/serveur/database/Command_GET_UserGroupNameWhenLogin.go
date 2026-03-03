package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

func GetUserGroupNameWhenLogin(db *sql.DB, username, computeur_id string) (string, error) {
	injection := SanitizeInput(username, computeur_id)
	if injection != nil {
		return "", injection
	}

	var userID int
	// Récupère l'ID de l'utilisateur basé sur le username
	query := `SELECT id_user FROM users WHERE username = ?`
	err := db.QueryRow(query, username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			logs.WriteLog("db", "Utilisateur non trouvé: "+username)
			return "", fmt.Errorf("utilisateur non trouvé")
		}
		logs.WriteLog("db", "Erreur lors de la récupération de l'ID utilisateur: "+err.Error())
		return "", err
	}

	// Vérification si l'utilisateur et l'ordinateur partagent une permission (via users_permission et id_logiciels)
	// -> Si tu veux aussi récupérer un "nom de permission" ici, tu peux, mais tu voulais "groupe", donc on saute cette partie pour l’instant.

	// Vérification si l'utilisateur et l'ordinateur partagent un groupe via `users_group` et `logiciel_group`
	var groupName string
	query = `SELECT groups.group_name FROM users_group
	         JOIN groups ON users_group.d_id_group = groups.id_group
	         JOIN logiciel_group ON groups.id_group = logiciel_group.d_id_group
	         JOIN id_logiciels ON logiciel_group.d_id_logiciel = id_logiciels.id_logiciel
	         WHERE users_group.d_id_user = ? AND id_logiciels.computeur_id = ? LIMIT 1`
	err = db.QueryRow(query, userID, computeur_id).Scan(&groupName)
	if err == nil && groupName != "" {
		logs.WriteLog("db", "Utilisateur "+username+" appartient au groupe "+groupName+".")
		return groupName, nil
	} else if err != sql.ErrNoRows {
		logs.WriteLog("db", "Erreur lors de la récupération du groupe: "+err.Error())
		return "", err
	}

	// Si aucune correspondance trouvée
	logs.WriteLog("db", "L'utilisateur "+username+" n'appartient à aucun groupe lié au client "+computeur_id)
	return "", nil
}
