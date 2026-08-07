package dbgpo

import (
	"database/sql"
	"fmt"
	"time"
)

// ComplianceRow est l'état de conformité d'un scope sur une machine.
type ComplianceRow struct {
	ComputeurID    string
	Scope          string
	TargetUser     string
	Fingerprint    string
	Status         string
	ModulesTotal   int
	ModulesFailed  int
	ModulesSkipped int
	ReportedAt     time.Time
	DriftCount     int
	DriftChecked   int
	DriftAt        sql.NullTime
}

const complianceSelect = `
	SELECT computeur_id, scope, target_user, fingerprint, status,
	       modules_total, modules_failed, modules_skipped, reported_at,
	       drift_count, drift_checked, drift_at
	  FROM gpo_compliance`

// ListCompliance retourne l'état du parc, machine par machine.
//
// L'ordre place devant ce qui va mal : un administrateur qui tape la commande
// cherche ce qui ne va pas, et le lui faire chercher dans une liste triée par
// nom rendrait la commande inutile au-delà de vingt machines.
func ListCompliance(db *sql.DB) ([]ComplianceRow, error) {
	if db == nil {
		return nil, fmt.Errorf("gpo: connexion base indisponible")
	}
	rows, err := db.Query(complianceSelect + `
		ORDER BY (modules_failed > 0) DESC, drift_count DESC, computeur_id, scope, target_user`)
	if err != nil {
		return nil, fmt.Errorf("gpo: lecture de la conformité : %w", err)
	}
	defer closeRows(rows)
	return scanCompliance(rows)
}

// GetComplianceForClient retourne les scopes d'une seule machine.
func GetComplianceForClient(db *sql.DB, computeurID string) ([]ComplianceRow, error) {
	if db == nil {
		return nil, fmt.Errorf("gpo: connexion base indisponible")
	}
	rows, err := db.Query(complianceSelect+`
		WHERE computeur_id = ?
		ORDER BY scope, target_user`, computeurID)
	if err != nil {
		return nil, fmt.Errorf("gpo: lecture de la conformité : %w", err)
	}
	defer closeRows(rows)
	return scanCompliance(rows)
}

func scanCompliance(rows *sql.Rows) ([]ComplianceRow, error) {
	var out []ComplianceRow
	for rows.Next() {
		var r ComplianceRow
		if err := rows.Scan(&r.ComputeurID, &r.Scope, &r.TargetUser, &r.Fingerprint, &r.Status,
			&r.ModulesTotal, &r.ModulesFailed, &r.ModulesSkipped, &r.ReportedAt,
			&r.DriftCount, &r.DriftChecked, &r.DriftAt); err != nil {
			return nil, fmt.Errorf("gpo: lecture d'une ligne de conformité : %w", err)
		}
		out = append(out, r)
	}
	// rows.Err() et pas seulement la fin de boucle : une connexion coupée en
	// cours de parcours termine la boucle SANS erreur, et le rapport
	// afficherait alors un parc partiel comme s'il était complet.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("gpo: parcours de la conformité : %w", err)
	}
	return out, nil
}

// ModuleReportRow est le détail d'un module, tel que relu.
type ModuleReportRow struct {
	Scope      string
	TargetUser string
	ModuleType string
	StateKey   string
	Result     string
	Detail     string
}

// GetModuleReports retourne le détail par module d'une machine.
func GetModuleReports(db *sql.DB, computeurID string) ([]ModuleReportRow, error) {
	if db == nil {
		return nil, fmt.Errorf("gpo: connexion base indisponible")
	}
	rows, err := db.Query(`
		SELECT scope, target_user, module_type, state_key, result, COALESCE(detail, '')
		  FROM gpo_module_report
		 WHERE computeur_id = ?
		 -- Les échecs d'abord : c'est ce qu'on vient lire.
		 ORDER BY (result = 'failed') DESC, scope, target_user, state_key`, computeurID)
	if err != nil {
		return nil, fmt.Errorf("gpo: lecture du détail des modules : %w", err)
	}
	defer closeRows(rows)

	var out []ModuleReportRow
	for rows.Next() {
		var r ModuleReportRow
		if err := rows.Scan(&r.Scope, &r.TargetUser, &r.ModuleType, &r.StateKey, &r.Result, &r.Detail); err != nil {
			return nil, fmt.Errorf("gpo: lecture d'un module : %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("gpo: parcours du détail des modules : %w", err)
	}
	return out, nil
}

// DriftRow est un écart, tel que relu.
type DriftRow struct {
	Scope      string
	TargetUser string
	StateKey   string
	Kind       string
	Path       string
	Detail     string
	DetectedAt time.Time
}

// GetDriftForClient retourne les écarts constatés sur une machine.
func GetDriftForClient(db *sql.DB, computeurID string) ([]DriftRow, error) {
	if db == nil {
		return nil, fmt.Errorf("gpo: connexion base indisponible")
	}
	rows, err := db.Query(`
		SELECT scope, target_user, state_key, kind, path, COALESCE(detail, ''), detected_at
		  FROM gpo_drift
		 WHERE computeur_id = ?
		 ORDER BY scope, target_user, path`, computeurID)
	if err != nil {
		return nil, fmt.Errorf("gpo: lecture des écarts : %w", err)
	}
	defer closeRows(rows)

	var out []DriftRow
	for rows.Next() {
		var r DriftRow
		if err := rows.Scan(&r.Scope, &r.TargetUser, &r.StateKey, &r.Kind, &r.Path, &r.Detail, &r.DetectedAt); err != nil {
			return nil, fmt.Errorf("gpo: lecture d'un écart : %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("gpo: parcours des écarts : %w", err)
	}
	return out, nil
}
