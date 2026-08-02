package db_revocation

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// Record est un ordre tel qu'il est stocké, avec sa trace d'audit.
type Record struct {
	ID        int
	Username  string
	Mode      revocation.Mode
	Reason    revocation.Reason
	IssuedBy  string
	IssuedAt  time.Time
	LiftedBy  string
	LiftedAt  sql.NullTime
	Pending   int // machines restant à traiter
	Total     int // machines visées
}

// IsActive dit si l'ordre est toujours en vigueur.
func (r Record) IsActive() bool { return !r.LiftedAt.Valid }

// TargetRecord est l'état d'un ordre pour une machine.
type TargetRecord struct {
	ComputeurID string
	Status      revocation.TargetStatus
	LastAttempt sql.NullTime
	Detail      string
}

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

// IsRevoked dit si un compte porte un verrouillage soft actif.
//
// LECTURE FAIL-CLOSED : en cas d'erreur de base, la fonction retourne true.
// C'est délibéré et c'est l'inverse du réflexe habituel. Cette fonction garde
// l'authentification : si la base ne répond pas, refuser une connexion
// légitime est un incident d'exploitation, tandis qu'accepter celle d'un compte
// compromis est un incident de sécurité. Le compte d'amorçage `vaultaire` ne
// pouvant pas être révoqué, il reste joignable pour diagnostiquer.
func IsRevoked(db *sql.DB, username string) bool {
	if db == nil {
		logs.Write_Log("ERROR", "revocation: base indisponible, "+username+" traité comme révoqué")
		return true
	}
	if err := database.SanitizeIdentifier(username); err != nil {
		return true
	}

	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM user_revocation
		 WHERE username = ? AND mode = ? AND lifted_at IS NULL`,
		username, string(revocation.ModeSoft)).Scan(&count)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, fmt.Sprintf(
			"revocation: lecture impossible pour %s, compte traité comme révoqué : %v", username, err))
		return true
	}
	return count > 0
}

// LiftSoftRevocations lève les verrouillages soft actifs d'un compte.
//
// Retourne le nombre de verrous levés, pour distinguer « déverrouillé » de
// « n'était pas verrouillé » — l'interface ne doit pas annoncer une action qui
// n'a rien changé.
func LiftSoftRevocations(db *sql.DB, username, liftedBy string) (int, error) {
	if err := database.SanitizeIdentifier(username, liftedBy); err != nil {
		return 0, err
	}

	res, err := db.Exec(
		`UPDATE user_revocation SET lifted_by = ?, lifted_at = NOW()
		 WHERE username = ? AND mode = ? AND lifted_at IS NULL`,
		liftedBy, username, string(revocation.ModeSoft))
	if err != nil {
		return 0, fmt.Errorf("levée du verrouillage : %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"revocation: verrouillage de %s levé par %s (%d ordre(s))", username, liftedBy, affected))
	}
	return int(affected), nil
}

// PendingOrdersForClient retourne les ordres qu'une machine n'a pas encore
// acquittés, du plus ancien au plus récent.
//
// L'ordre chronologique compte : un verrouillage suivi d'un déverrouillage doit
// être rejoué dans cet ordre, sinon la machine terminerait verrouillée alors
// que le compte a été rétabli.
func PendingOrdersForClient(db *sql.DB, computeurID string, limit int) ([]revocation.Order, error) {
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 200
	}

	rows, err := db.Query(
		`SELECT r.id_revocation, r.mode, r.username, r.reason_code
		   FROM user_revocation r
		   JOIN user_revocation_target t ON t.d_id_revocation = r.id_revocation
		  WHERE t.computeur_id = ? AND t.status <> ?
		  ORDER BY r.id_revocation ASC
		  LIMIT ?`,
		computeurID, string(revocation.StatusAcked), limit)
	if err != nil {
		return nil, fmt.Errorf("lecture des ordres en attente : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()

	var orders []revocation.Order
	for rows.Next() {
		var o revocation.Order
		var mode, reason string
		if err := rows.Scan(&o.ID, &mode, &o.Username, &reason); err != nil {
			return nil, fmt.Errorf("lecture d'un ordre : %w", err)
		}
		o.Mode = revocation.Mode(mode)
		o.Reason = revocation.Reason(reason)
		if err := o.Validate(); err != nil {
			// Une ligne corrompue n'interrompt pas les autres : mieux vaut
			// appliquer les ordres lisibles que de tout bloquer.
			logs.Write_LogCode("WARNING", logs.CodeDBQuery,
				"revocation: ordre illisible ignoré: "+err.Error())
			continue
		}
		orders = append(orders, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des ordres : %w", err)
	}
	return orders, nil
}

// MarkTarget enregistre le compte rendu d'une machine pour un ordre.
func MarkTarget(db *sql.DB, orderID int, computeurID string, status revocation.TargetStatus, detail string) error {
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return err
	}
	// Le détail vient de l'agent : borné pour ne pas laisser une machine écrire
	// un volume arbitraire dans la base du serveur.
	if len(detail) > 512 {
		detail = detail[:512]
	}

	_, err := db.Exec(
		`UPDATE user_revocation_target
		    SET status = ?, last_attempt = NOW(), detail = ?
		  WHERE d_id_revocation = ? AND computeur_id = ?`,
		string(status), detail, orderID, computeurID)
	if err != nil {
		return fmt.Errorf("mise à jour de la cible : %w", err)
	}
	return nil
}

// TargetsOf retourne l'état de toutes les machines visées par un ordre.
func TargetsOf(db *sql.DB, orderID int) ([]TargetRecord, error) {
	rows, err := db.Query(
		`SELECT computeur_id, status, last_attempt, COALESCE(detail, '')
		   FROM user_revocation_target
		  WHERE d_id_revocation = ?
		  ORDER BY computeur_id`, orderID)
	if err != nil {
		return nil, fmt.Errorf("lecture des cibles : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()

	var out []TargetRecord
	for rows.Next() {
		var t TargetRecord
		var status string
		if err := rows.Scan(&t.ComputeurID, &status, &t.LastAttempt, &t.Detail); err != nil {
			return nil, fmt.Errorf("lecture d'une cible : %w", err)
		}
		t.Status = revocation.TargetStatus(status)
		out = append(out, t)
	}
	return out, rows.Err()
}

// HistoryFor retourne l'historique des ordres visant un compte, du plus récent
// au plus ancien, avec l'avancement de chacun.
func HistoryFor(db *sql.DB, username string) ([]Record, error) {
	if err := database.SanitizeIdentifier(username); err != nil {
		return nil, err
	}
	return queryRecords(db,
		`SELECT r.id_revocation, r.username, r.mode, r.reason_code, r.issued_by, r.issued_at,
		        COALESCE(r.lifted_by, ''), r.lifted_at,
		        COALESCE(SUM(t.status <> 'acked'), 0), COALESCE(COUNT(t.computeur_id), 0)
		   FROM user_revocation r
		   LEFT JOIN user_revocation_target t ON t.d_id_revocation = r.id_revocation
		  WHERE r.username = ?
		  GROUP BY r.id_revocation
		  ORDER BY r.id_revocation DESC`, username)
}

// ActiveOrders retourne tous les verrouillages soft en vigueur, pour la vue
// d'ensemble de l'interface.
func ActiveOrders(db *sql.DB) ([]Record, error) {
	return queryRecords(db,
		`SELECT r.id_revocation, r.username, r.mode, r.reason_code, r.issued_by, r.issued_at,
		        COALESCE(r.lifted_by, ''), r.lifted_at,
		        COALESCE(SUM(t.status <> 'acked'), 0), COALESCE(COUNT(t.computeur_id), 0)
		   FROM user_revocation r
		   LEFT JOIN user_revocation_target t ON t.d_id_revocation = r.id_revocation
		  WHERE r.lifted_at IS NULL
		  GROUP BY r.id_revocation
		  ORDER BY r.issued_at DESC`)
}

// queryRecords factorise la lecture d'ordres, les deux requêtes ci-dessus ne
// différant que par leur clause WHERE.
func queryRecords(db *sql.DB, query string, args ...interface{}) ([]Record, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("lecture des révocations : %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			logs.Write_Log("DEBUG", "revocation: fermeture du curseur: "+cerr.Error())
		}
	}()

	var out []Record
	for rows.Next() {
		var r Record
		var mode, reason string
		if err := rows.Scan(&r.ID, &r.Username, &mode, &reason, &r.IssuedBy, &r.IssuedAt,
			&r.LiftedBy, &r.LiftedAt, &r.Pending, &r.Total); err != nil {
			return nil, fmt.Errorf("lecture d'une révocation : %w", err)
		}
		r.Mode = revocation.Mode(mode)
		r.Reason = revocation.Reason(reason)
		out = append(out, r)
	}
	return out, rows.Err()
}
