package dbpermission

import (
	"database/sql"
	"fmt"
	"log"
	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// colonnes legacy (table user_permission)
var legacyColumns = map[string]bool{
	"none": true, "web_admin": true, "auth": true, "compare": true, "search": true,
}

// GetPermissionContent récupère le contenu d'une action pour un groupe donné.
// Actions legacy (none, web_admin, auth, compare, search) : colonnes user_permission.
// Actions RBAC (catégorie:action:objet) : table user_permission_action.
func GetPermissionContent(db *sql.DB, groupID int, action string) (string, error) {
	var permissionID int
	if err := db.QueryRow("SELECT d_id_user_permission FROM group_user_permission WHERE d_id_group = ?", groupID).Scan(&permissionID); err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur récupération user_permission pour groupe %d: %v", groupID, err))
		return "", fmt.Errorf("erreur récupération user_permission pour le groupe %d: %v", groupID, err)
	}

	if legacyColumns[action] {
		var content string
		query := fmt.Sprintf("SELECT %s FROM user_permission WHERE id_user_permission = ?", action)
		if err := db.QueryRow(query, permissionID).Scan(&content); err != nil {
			logs.WriteLog("db", fmt.Sprintf("Erreur récupération action '%s' permission %d: %v", action, permissionID, err))
			return "", fmt.Errorf("erreur récupération action '%s': %v", action, err)
		}
		return content, nil
	}

	// int -> int64 : les deux appelants de actionValue ne s'accordent pas sur le
	// type de l'identifiant, héritage des deux époques du paquet.
	value, err := actionValue(db, int64(permissionID), action)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur récupération action_key '%s' permission %d: %v", action, permissionID, err))
		return "", err
	}
	return value, nil
}

// actionValue lit une action RBAC dans user_permission_action.
//
// L'absence de ligne rend "nil" et non une erreur : une action jamais renseignée
// vaut « pas accordée », qui est l'état par défaut de toute permission neuve.
func actionValue(db *sql.DB, permissionID int64, action string) (string, error) {
	var value string
	err := db.QueryRow(
		"SELECT value FROM user_permission_action WHERE id_user_permission = ? AND action_key = ?",
		permissionID, action,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return "nil", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

// Command_GET_UserPermissionAction récupère le contenu d'une action pour une permission (par ID).
// Actions legacy (none, web_admin, auth, compare, search) : colonne user_permission.
// Actions RBAC (catégorie:action:objet) : table user_permission_action.
func Command_GET_UserPermissionAction(db *sql.DB, id int64, action string) (string, error) {
	if legacyColumns[action] {
		query := fmt.Sprintf("SELECT %s FROM user_permission WHERE id_user_permission = ? LIMIT 1", action)
		var value string
		err := db.QueryRow(query, id).Scan(&value)
		if err != nil {
			return "", err
		}
		return value, nil
	}

	return actionValue(db, id, action)
}

// getPermissionNameByID résout le nom d'une permission depuis son identifiant.
//
// Une erreur (permission absente) n'est pas traitée comme un refus par
// l'appelant : l'écriture qui suit échouera de toute façon sur une permission
// inexistante, et bloquer ici masquerait la vraie cause.
func getPermissionNameByID(db *sql.DB, id int64) (string, error) {
	var name string
	err := db.QueryRow(
		"SELECT name FROM user_permission WHERE id_user_permission = ? LIMIT 1", id,
	).Scan(&name)
	return name, err
}

// Command_SET_UserPermissionAction met à jour le contenu d'une action.
// Actions legacy : UPDATE user_permission. Actions RBAC : INSERT/UPDATE user_permission_action.
func Command_SET_UserPermissionAction(db *sql.DB, id int64, action string, newValue string) error {
	// La permission d'amorçage n'est pas modifiable, y compris de l'intérieur.
	// Le contrôle porte sur l'identifiant reçu, pas sur un nom passé par
	// l'appelant : c'est la seule façon de couvrir tous les chemins, y compris
	// ceux qui ne connaissent que l'ID.
	if name, err := getPermissionNameByID(db, id); err == nil {
		if guardErr := database.GuardProtectedPermissionContent(name, action); guardErr != nil {
			return guardErr
		}
	}

	if legacyColumns[action] {
		query := fmt.Sprintf("UPDATE user_permission SET %s = ? WHERE id_user_permission = ?", action)
		_, err := db.Exec(query, newValue, id)
		if err != nil {
			logs.WriteLog("db", fmt.Sprintf("SET legacy action '%s' permission %d: %v", action, id, err))
			return err
		}
		return nil
	}

	_, err := db.Exec(
		`INSERT INTO user_permission_action (id_user_permission, action_key, value) VALUES (?, ?, ?)
		 ON DUPLICATE KEY UPDATE value = VALUES(value)`,
		id, action, newValue,
	)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("SET action_key '%s' permission %d: %v", action, id, err))
		return err
	}
	return nil
}

// GetUserPermissionsForAction récupère toutes les valeurs d'action d'un utilisateur
func GetUserPermissionsForAction(db *sql.DB, username, action string) ([]string, error) {
	injection := database.SanitizeIdentifier(username, action)
	if injection != nil {
		return nil, nil
	}

	query := `
		SELECT up.` + action + `
		FROM users u
		JOIN users_group ug ON u.id_user = ug.d_id_user
		JOIN group_user_permission gup ON ug.d_id_group = gup.d_id_group
		JOIN user_permission up ON gup.d_id_user_permission = up.id_user_permission
		WHERE u.username = ?
	`

	rows, err := db.Query(query, username)
	if err != nil {
		log.Printf("Erreur SQL : %v", err)
		return nil, err
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var rawValue string
		if err := rows.Scan(&rawValue); err != nil {
			log.Printf("Erreur Scan : %v", err)
			continue
		}
		results = append(results, rawValue)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
