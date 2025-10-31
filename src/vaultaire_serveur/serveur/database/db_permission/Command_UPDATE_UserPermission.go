package db_permission

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

func UpdateUserPermissionBooleanField(db *sql.DB, permissionName string, column string, value bool) error {
	// Liste blanche des colonnes valides à modifier
	validColumns := map[string]bool{
		"none":                 true,
		"web_admin":            true,
		"auth":                 true,
		"compare":              true,
		"search":               true,
		"can_read":             true,
		"can_write":            true,
		"api_read_permission":  true,
		"api_write_permission": true,
	}

	// Vérifie que la colonne est bien autorisée
	if !validColumns[column] {
		logs.WriteLog("db", "colonne invalide : "+column)
		return fmt.Errorf("colonne invalide : %s -> Voila la liste des colone valide auth, compare, search, can_read, can_write", column)
	}

	// Prépare dynamiquement la requête SQL (en toute sécurité car column est validée)
	query := fmt.Sprintf("UPDATE user_permission SET %s = ? WHERE name = ?", column)

	// Exécute la requête avec les arguments
	_, err := db.Exec(query, value, permissionName)
	if err != nil {
		logs.WriteLog("db", "échec de la mise à jour de la permission : "+err.Error())
		return fmt.Errorf("échec de la mise à jour de la permission : %w", err)
	}

	return nil
}
