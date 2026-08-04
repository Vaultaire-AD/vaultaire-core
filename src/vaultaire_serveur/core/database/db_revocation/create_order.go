package dbrevocation

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// CreateOrder écrit un ordre et la liste des machines qu'il vise.
//
// L'écriture est transactionnelle : un ordre sans ses cibles serait un ordre qui
// ne part jamais, et des cibles sans ordre seraient orphelines. Les deux
// doivent apparaître ensemble ou pas du tout.
func CreateOrder(db *sql.DB, username string, mode revocation.Mode, reason revocation.Reason,
	issuedBy string, targets []string) (int, error) {

	if err := database.SanitizeIdentifier(username, issuedBy); err != nil {
		return 0, err
	}
	if !revocation.IsValidMode(mode) {
		return 0, fmt.Errorf("mode inconnu %q", mode)
	}
	if !revocation.IsValidReason(reason) {
		return 0, fmt.Errorf("motif inconnu %q", reason)
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("ouverture de transaction : %w", err)
	}
	defer func() {
		// Rollback après un Commit réussi est sans effet : ce defer ne sert
		// qu'aux sorties en erreur, sans qu'il faille le répéter partout.
		_ = tx.Rollback()
	}()

	res, err := tx.Exec(
		`INSERT INTO user_revocation (username, mode, reason_code, issued_by)
		 VALUES (?, ?, ?, ?)`,
		username, string(mode), string(reason), issuedBy)
	if err != nil {
		return 0, fmt.Errorf("écriture de l'ordre : %w", err)
	}
	id64, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("identifiant de l'ordre : %w", err)
	}
	orderID := int(id64)

	for _, computeurID := range targets {
		if strings.TrimSpace(computeurID) == "" {
			continue
		}
		if _, err := tx.Exec(
			`INSERT IGNORE INTO user_revocation_target (d_id_revocation, computeur_id, status)
			 VALUES (?, ?, ?)`,
			orderID, computeurID, string(revocation.StatusPending)); err != nil {
			return 0, fmt.Errorf("écriture d'une cible : %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("validation de la transaction : %w", err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"revocation: ordre %d créé par %s — %s sur %s (motif %s), %d machine(s) visée(s)",
		orderID, issuedBy, mode, username, reason, len(targets)))

	return orderID, nil
}
