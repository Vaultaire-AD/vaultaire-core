package dbusers

import (
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/storage"
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
	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}
