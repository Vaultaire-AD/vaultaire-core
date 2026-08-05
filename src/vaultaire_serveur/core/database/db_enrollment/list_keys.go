package dbenrollment

import (
	"database/sql"
	"fmt"

	"vaultaire/core/logs"
)

// ListKeys retourne les clés d'enrôlement, les plus récentes d'abord.
//
// Les clés révoquées, expirées et épuisées sont incluses : la question « qui a
// émis une clé pour ce type, et quand ? » se pose surtout après coup.
func ListKeys(db *sql.DB) ([]Record, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}
	rows, err := db.Query(
		`SELECT id_key, label, client_type, max_uses, used_count,
		        expires_at, created_by, created_at, revoked_by, revoked_at
		   FROM service_enrollment_key
		  ORDER BY created_at DESC, id_key DESC`)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dbenrollment: lecture des clés échouée : "+err.Error())
		return nil, fmt.Errorf("lecture des clés d'enrôlement : %w", err)
	}
	defer closeRows(rows)

	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Label, &r.ClientType, &r.MaxUses, &r.UsedCount,
			&r.ExpiresAt, &r.CreatedBy, &r.CreatedAt, &r.RevokedBy, &r.RevokedAt); err != nil {
			return nil, fmt.Errorf("lecture d'une clé : %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des clés : %w", err)
	}
	return out, nil
}

// UsesOf retourne les services entrés par une clé.
//
// C'est la réponse à « qu'est-ce qui est entré avec cette clé ? », posée le jour
// où l'on découvre qu'elle a fuité.
func UsesOf(db *sql.DB, keyID int) ([]Use, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}
	rows, err := db.Query(
		`SELECT computeur_id, client_type, source_ip, used_at
		   FROM service_enrollment_use
		  WHERE d_id_key = ?
		  ORDER BY used_at DESC`, keyID)
	if err != nil {
		return nil, fmt.Errorf("lecture des consommations : %w", err)
	}
	defer closeRows(rows)

	var out []Use
	for rows.Next() {
		var u Use
		if err := rows.Scan(&u.ComputeurID, &u.ClientType, &u.SourceIP, &u.UsedAt); err != nil {
			return nil, fmt.Errorf("lecture d'une consommation : %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des consommations : %w", err)
	}
	return out, nil
}

func closeRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		logs.Write_Log("ERROR", "dbenrollment: fermeture du curseur : "+err.Error())
	}
}
