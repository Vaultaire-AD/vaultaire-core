package dbgpo

import (
	"database/sql"
	"fmt"
	"time"
	"vaultaire/core/database"
)

// ModuleReport est le résultat d'un module, tel que rapporté par l'agent.
type ModuleReport struct {
	ModuleType string
	StateKey   string
	Result     string
	Detail     string
}

// SaveApplyReport enregistre un rapport d'application.
//
// # Pourquoi une transaction
//
// L'état courant et son détail par module doivent bouger ensemble. Sans
// transaction, une panne entre les deux laisserait un statut « applied » avec le
// détail de l'application PRÉCÉDENTE — c'est-à-dire une machine affichée comme
// conforme avec la liste des modules qui avaient échoué la fois d'avant. Plus
// trompeur que pas d'information du tout.
func SaveApplyReport(db *sql.DB, computeurID, scope, targetUser, fingerprint, status string,
	version int, modules []ModuleReport) error {

	if db == nil {
		return fmt.Errorf("gpo: connexion base indisponible")
	}
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return err
	}

	var échoués, ignorés int
	for _, m := range modules {
		switch m.Result {
		case "failed":
			échoués++
		case "skipped":
			ignorés++
		}
	}

	maintenant := time.Now().UTC()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("gpo: transaction impossible : %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// ON DUPLICATE KEY UPDATE plutôt qu'un DELETE suivi d'un INSERT : la ligne
	// reste visible en permanence, et une lecture concurrente ne tombe jamais
	// sur une machine momentanément absente de la table.
	//
	// Les colonnes de dérive ne sont PAS touchées ici : elles viennent du scan
	// de conformité, qui a son propre rythme. Les remettre à zéro à chaque
	// application effacerait un écart constaté que rien n'a encore corrigé.
	if _, err := tx.Exec(`
		INSERT INTO gpo_compliance
			(computeur_id, scope, target_user, policy_version, fingerprint, status,
			 modules_total, modules_failed, modules_skipped, reported_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			policy_version  = VALUES(policy_version),
			fingerprint     = VALUES(fingerprint),
			status          = VALUES(status),
			modules_total   = VALUES(modules_total),
			modules_failed  = VALUES(modules_failed),
			modules_skipped = VALUES(modules_skipped),
			reported_at     = VALUES(reported_at)`,
		computeurID, scope, targetUser, version, fingerprint, status,
		len(modules), échoués, ignorés, maintenant); err != nil {
		return fmt.Errorf("gpo: enregistrement de la conformité : %w", err)
	}

	// Le détail est REMPLACÉ, pas complété : il décrit le dernier rapport, et
	// mélanger deux applications donnerait un module apparaissant à la fois en
	// échec et en succès.
	if _, err := tx.Exec(
		`DELETE FROM gpo_module_report WHERE computeur_id = ? AND scope = ? AND target_user = ?`,
		computeurID, scope, targetUser); err != nil {
		return fmt.Errorf("gpo: nettoyage du détail : %w", err)
	}

	for _, m := range modules {
		if _, err := tx.Exec(`
			INSERT INTO gpo_module_report
				(computeur_id, scope, target_user, module_type, state_key, result, detail, reported_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			computeurID, scope, targetUser, m.ModuleType, m.StateKey, m.Result, m.Detail, maintenant); err != nil {
			return fmt.Errorf("gpo: enregistrement du module %s : %w", m.StateKey, err)
		}
	}

	return tx.Commit()
}
