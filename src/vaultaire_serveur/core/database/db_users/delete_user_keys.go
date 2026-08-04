package dbusers

import (
	"fmt"
	"vaultaire/core/database"
)

// DeleteUserKeys supprime une ou plusieurs clés par ID
func DeleteUserKeys(keyIDs []int) error {
	db := database.GetDatabase()
	if len(keyIDs) == 0 {
		return nil
	}

	// Préparer la clause IN (?, ?, ?)
	args := make([]interface{}, len(keyIDs))
	placeholders := ""
	for i, id := range keyIDs {
		args[i] = id
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
	}

	query := fmt.Sprintf("DELETE FROM user_public_keys WHERE id_key IN (%s)", placeholders)
	_, err := db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("Erreur suppression clés : %v", err)
	}
	return nil
}
