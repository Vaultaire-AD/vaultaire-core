package dbuser

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/storage"
	"fmt"
)

// GetUserKeys récupère toutes les clés publiques d'un utilisateur
func GetUserKeys(userID int) ([]storage.PublicKey, error) {
	db := database.GetDatabase()
	rows, err := db.Query("SELECT id_key, id_user, public_key, label, created_at FROM user_public_keys WHERE id_user = ?", userID)
	if err != nil {
		return nil, fmt.Errorf("Erreur récupération clés : %v", err)
	}
	defer rows.Close()

	var keys []storage.PublicKey
	for rows.Next() {
		var k storage.PublicKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Key, &k.Label, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("Erreur scan clé : %v", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// AddUserKey ajoute une nouvelle clé publique pour un utilisateur
func AddUserKey(userID int, publicKey, label string) error {
	db := database.GetDatabase()
	_, err := db.Exec("INSERT INTO user_public_keys (id_user, public_key, label) VALUES (?, ?, ?)", userID, publicKey, label)
	if err != nil {
		return fmt.Errorf("Erreur ajout clé publique : %v", err)
	}
	return nil
}

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
