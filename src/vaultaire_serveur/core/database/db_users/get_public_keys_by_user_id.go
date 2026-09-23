package dbusers

import (
	"database/sql"
	"fmt"
)

func Get_PublicKeys_ByUserID(db *sql.DB, userID int) ([]string, error) {
	query := `SELECT public_key FROM user_public_keys WHERE id_user = ?`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("erreur requête DB: %w", err)
	}
	defer rows.Close()

	var keys []string

	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("erreur scan clé publique: %w", err)
		}
		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erreur itération rows: %w", err)
	}

	// AUCUNE CLÉ N'EST PAS UNE ERREUR.
	//
	// Cette fonction rendait une erreur quand la table ne portait aucune ligne,
	// et l'appelant de 03_01 en faisait un REFUS D'AUTHENTIFICATION : un compte
	// sans clé publique ne pouvait donc ouvrir aucune session, pas même par mot
	// de passe. Le défaut est resté invisible tant que tout compte de test avait
	// une clé ; il saute aux yeux sur un poste Windows, où les clés SSH n'ont
	// aucun sens et où personne n'en dépose.
	//
	// L'absence et l'échec ne se confondent plus : une liste vide se lit avec
	// len(), une panne de base reste une erreur.
	return keys, nil
}
