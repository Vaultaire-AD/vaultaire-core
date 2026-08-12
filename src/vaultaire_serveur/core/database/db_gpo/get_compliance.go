package dbgpo

import (
	"database/sql"
	"fmt"
	"time"

	"vaultaire/core/clienttype"
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

	// JamaisRapporte : la machine est à l'inventaire, elle n'a jamais rapporté.
	//
	// Ce n'est pas une valeur lue en base — c'est une ligne qui n'existe PAS
	// dans gpo_compliance, et c'est précisément l'information qui manquait.
	// Voir ListCompliance.
	JamaisRapporte bool
}

const complianceSelect = `
	SELECT computeur_id, scope, target_user, fingerprint, status,
	       modules_total, modules_failed, modules_skipped, reported_at,
	       drift_count, drift_checked, drift_at
	  FROM gpo_compliance`

// listeParcSelect part de l'INVENTAIRE des machines, pas des rapports.
//
// # Le défaut que cette jointure corrige
//
// La version précédente lisait `FROM gpo_compliance`. Une machine qui n'a
// jamais rapporté n'a pas de ligne dans cette table : elle ne s'affichait donc
// ni en échec, ni en retard — elle ne s'affichait PAS.
//
// C'est le pire des trois états possibles présenté comme le meilleur. Un agent
// mort, un service arrêté, une machine jamais installée : autant de silences
// qui se lisaient comme une absence de problème. La question à laquelle cette
// vue doit répondre — « quelles machines sont en échec ou en retard » — n'avait
// de réponse que pour celles qui parlaient encore.
//
// La LEFT JOIN renverse la source de vérité : c'est l'inventaire qui décide
// quelles machines doivent apparaître, et le rapport qui vient s'y accrocher
// quand il existe.
//
// # Pourquoi seuls les agents
//
// Un proxy ou l'interface web ne reçoivent aucune politique : les faire
// apparaître comme « jamais rapporté » remplirait la vue de faux positifs
// permanents, et le premier réflexe serait de désactiver la colonne.
const listeParcSelect = `
	SELECT l.computeur_id,
	       COALESCE(c.scope, ''), COALESCE(c.target_user, ''),
	       COALESCE(c.fingerprint, ''), COALESCE(c.status, ''),
	       COALESCE(c.modules_total, 0), COALESCE(c.modules_failed, 0),
	       COALESCE(c.modules_skipped, 0),
	       c.reported_at,
	       COALESCE(c.drift_count, 0), COALESCE(c.drift_checked, 0),
	       c.drift_at
	  FROM id_logiciels l
	  LEFT JOIN gpo_compliance c ON c.computeur_id = l.computeur_id
	 WHERE l.logiciel_type = ?`

// ListCompliance retourne l'état du parc, machine par machine.
//
// L'ordre place devant ce qui va mal — voir TrierConformite. Il est calculé en
// Go et non par la base : il dépend de l'heure courante, et un tri qu'on ne
// peut pas éprouver sans base est un tri que personne ne vérifie.
func ListCompliance(db *sql.DB) ([]ComplianceRow, error) {
	if db == nil {
		return nil, fmt.Errorf("gpo: connexion base indisponible")
	}
	rows, err := db.Query(listeParcSelect, clienttype.Client)
	if err != nil {
		return nil, fmt.Errorf("gpo: lecture de la conformité : %w", err)
	}
	defer closeRows(rows)

	out, err := scanCompliance(rows)
	if err != nil {
		return nil, err
	}
	TrierConformite(out, time.Now())
	return out, nil
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
		// reported_at est lu en NullTime et non en time.Time.
		//
		// La colonne est NOT NULL dans gpo_compliance, mais la LEFT JOIN de
		// listeParcSelect produit un NULL pour toute machine sans rapport —
		// c'est justement la ligne qu'on cherche à faire apparaître. Scanner
		// dans un time.Time échouerait sur ces lignes-là, et la vue
		// retomberait sur les seules machines qui parlent.
		var rapporteA sql.NullTime
		if err := rows.Scan(&r.ComputeurID, &r.Scope, &r.TargetUser, &r.Fingerprint, &r.Status,
			&r.ModulesTotal, &r.ModulesFailed, &r.ModulesSkipped, &rapporteA,
			&r.DriftCount, &r.DriftChecked, &r.DriftAt); err != nil {
			return nil, fmt.Errorf("gpo: lecture d'une ligne de conformité : %w", err)
		}
		out = append(out, NormaliserLigne(r, rapporteA))
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
