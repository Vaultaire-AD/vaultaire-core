package dbusers

import (
	"database/sql"
)

// usernameHoldingKey retourne le compte détenant une clé publique.
//
// La comparaison porte sur les 255 premiers caractères, exactement comme
// l'index `unique_pubkey (public_key(255))`. Comparer la chaîne entière ferait
// répondre « aucun » là où la base vient pourtant de refuser l'insertion — le
// message serait alors plus déroutant que l'erreur brute qu'il remplace.
func usernameHoldingKey(db *sql.DB, publicKey string) (string, error) {
	var username string
	err := db.QueryRow(`
		SELECT u.username
		  FROM user_public_keys k
		  JOIN users u ON u.id_user = k.id_user
		 WHERE LEFT(k.public_key, 255) = LEFT(?, 255)
		 LIMIT 1`, publicKey).Scan(&username)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return username, err
}
