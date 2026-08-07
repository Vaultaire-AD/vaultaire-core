package dbgpo

import (
	"database/sql"
	"fmt"
	"time"
	"vaultaire/core/database"
)

// DriftEntry est un écart constaté, tel qu'il arrive de l'agent.
type DriftEntry struct {
	StateKey string
	Kind     string
	Path     string
	Detail   string
}

// maxDriftEntries borne ce qu'un seul rapport peut écrire.
//
// Une machine dont le disque système a été remonté ailleurs signale TOUS ses
// fichiers gérés comme manquants d'un coup. C'est légitime, mais mille machines
// dans cet état écriraient un volume que rien ne relit — et la centième ligne
// n'apprend déjà plus rien à personne. Au-delà, on tronque et on le dit dans le
// compte, qui lui reste exact.
const maxDriftEntries = 200

// SaveDriftReport enregistre un rapport de conformité.
//
// # Pourquoi la ligne de conformité est créée si elle manque
//
// Un agent peut scanner avant d'avoir rapporté une application — au tout premier
// cycle après une mise à jour, par exemple. Refuser le rapport dans ce cas
// perdrait précisément l'information la plus intéressante : une machine qui
// dérive sans qu'on sache ce qu'elle a appliqué.
func SaveDriftReport(db *sql.DB, computeurID, scope, targetUser string,
	checked int, entries []DriftEntry) error {

	if db == nil {
		return fmt.Errorf("gpo: connexion base indisponible")
	}
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return err
	}

	total := len(entries)
	if len(entries) > maxDriftEntries {
		entries = entries[:maxDriftEntries]
	}

	maintenant := time.Now().UTC()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("gpo: transaction impossible : %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// drift_count porte le total AVANT troncature : le tableau de bord doit
	// afficher « 4000 écarts » même si seuls les 200 premiers sont détaillés.
	// Compter les lignes enregistrées afficherait 200 et laisserait croire que
	// la situation est quatre fois moins grave qu'elle ne l'est.
	if _, err := tx.Exec(`
		INSERT INTO gpo_compliance
			(computeur_id, scope, target_user, reported_at, drift_count, drift_checked, drift_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			drift_count   = VALUES(drift_count),
			drift_checked = VALUES(drift_checked),
			drift_at      = VALUES(drift_at)`,
		computeurID, scope, targetUser, maintenant, total, checked, maintenant); err != nil {
		return fmt.Errorf("gpo: enregistrement de la dérive : %w", err)
	}

	if _, err := tx.Exec(
		`DELETE FROM gpo_drift WHERE computeur_id = ? AND scope = ? AND target_user = ?`,
		computeurID, scope, targetUser); err != nil {
		return fmt.Errorf("gpo: nettoyage des écarts : %w", err)
	}

	for _, e := range entries {
		if _, err := tx.Exec(`
			INSERT INTO gpo_drift
				(computeur_id, scope, target_user, state_key, kind, path, detail, detected_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			computeurID, scope, targetUser, e.StateKey, e.Kind, e.Path, e.Detail, maintenant); err != nil {
			return fmt.Errorf("gpo: enregistrement d'un écart : %w", err)
		}
	}

	return tx.Commit()
}

// ForgetCompliance efface le suivi d'une machine.
//
// Appelée à la suppression d'un client : sans elle, une machine mise au rebut
// resterait indéfiniment dans le rapport de parc, en échec, sans qu'aucune
// action ne puisse la corriger.
func ForgetCompliance(db *sql.DB, computeurID string) error {
	if db == nil {
		return fmt.Errorf("gpo: connexion base indisponible")
	}
	for _, table := range []string{"gpo_drift", "gpo_module_report", "gpo_compliance"} {
		if _, err := db.Exec("DELETE FROM "+table+" WHERE computeur_id = ?", computeurID); err != nil {
			return fmt.Errorf("gpo: purge de %s : %w", table, err)
		}
	}
	return nil
}
