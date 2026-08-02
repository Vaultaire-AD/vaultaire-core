package dbuser

import (
	"database/sql"
	"fmt"
	"strings"

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

// AddUserKey ajoute une nouvelle clé publique pour un utilisateur.
//
// UNE CLÉ N'APPARTIENT QU'À UN SEUL COMPTE. La contrainte `unique_pubkey` de
// user_public_keys est globale, pas par utilisateur, et c'est délibéré : l'API
// authentifie par signature SSH (voir core/api), donc une clé partagée entre
// deux comptes permettrait à son porteur d'agir sous l'une ou l'autre identité,
// au choix, à chaque requête. Le journal d'audit n'enregistrerait alors que le
// nom qu'il a bien voulu déclarer. Et révoquer une clé compromise obligerait à
// la chercher sur tous les comptes au lieu d'un seul.
//
// L'erreur brute de MySQL — « Error 1062 (23000): Duplicate entry 'ssh-rsa
// AAAAB3...' » — remontait telle quelle jusqu'à l'administrateur : illisible, et
// muette sur la seule information utile, à savoir QUEL compte détient déjà la
// clé. On la traduit.
func AddUserKey(userID int, publicKey, label string) error {
	db := database.GetDatabase()
	_, err := db.Exec("INSERT INTO user_public_keys (id_user, public_key, label) VALUES (?, ?, ?)", userID, publicKey, label)
	if err == nil {
		return nil
	}

	// La détection porte sur le texte de l'erreur plutôt que sur le type
	// *mysql.MySQLError : le pilote n'est importé qu'en effet de bord dans tout
	// le projet, et le remonter ici pour un seul message ferait entrer un
	// détail de pilote dans une couche qui n'en a pas besoin ailleurs.
	if strings.Contains(err.Error(), "1062") || strings.Contains(err.Error(), "Duplicate entry") {
		if owner, lookupErr := usernameHoldingKey(db, publicKey); lookupErr == nil && owner != "" {
			return fmt.Errorf(
				"cette clé publique est déjà enregistrée sur le compte %q — une clé n'appartient qu'à un seul compte, "+
					"sans quoi son porteur pourrait agir sous l'une ou l'autre identité sans que le journal permette de trancher. "+
					"Retirez-la de %q, ou générez une clé distincte pour ce compte", owner, owner)
		}
		return fmt.Errorf(
			"cette clé publique est déjà enregistrée sur un autre compte — une clé n'appartient qu'à un seul compte")
	}

	return fmt.Errorf("ajout de la clé publique impossible : %v", err)
}

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
