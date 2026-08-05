package dbenrollment

import (
	"database/sql"
	"fmt"
	"time"

	"vaultaire/core/logs"
)

// CreateKey enregistre une nouvelle clé d'enrôlement et retourne son
// identifiant.
//
// Le SECRET n'est pas un paramètre de sortie : l'appelant l'a généré, il le
// montre une fois, et il ne peut plus le retrouver ensuite. C'est délibéré — une
// clé qu'on peut relire est une clé qu'on finit par relire.
func CreateKey(db *sql.DB, secret, label, clientType string, maxUses int, expiresAt time.Time, createdBy string) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("connexion base indisponible")
	}
	if maxUses < 1 {
		return 0, fmt.Errorf("le quota d'utilisations doit valoir au moins 1")
	}
	if !expiresAt.After(time.Now()) {
		return 0, fmt.Errorf("la date d'expiration doit être dans le futur")
	}

	res, err := db.Exec(
		`INSERT INTO service_enrollment_key
		   (key_hash, label, client_type, max_uses, expires_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		HashSecret(secret), label, clientType, maxUses, expiresAt.UTC(), createdBy)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dbenrollment: insertion de clé échouée : "+err.Error())
		return 0, fmt.Errorf("enregistrement de la clé : %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("identifiant de la clé : %w", err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"enrôlement: %s a émis une clé pour le type %s (quota %d, expire le %s)",
		createdBy, clientType, maxUses, expiresAt.UTC().Format(time.RFC3339)))
	return int(id), nil
}
