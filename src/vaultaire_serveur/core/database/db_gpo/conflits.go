package dbgpo

import (
	"database/sql"
	"fmt"
	"time"
)

// Les conflits entre GPO d'une machine — TO-DO 222.
//
// Deux GPO liées à une même machine qui règlent la même chose autrement : la
// résolution écarte les modules qui s'opposent et livre le reste. Le conflit
// doit se VOIR ailleurs que dans le journal du core qui a servi la machine :
// il est rangé ici, par machine, scope et compte, à chaque résolution, et
// effacé dès qu'une résolution n'en trouve plus. `vlt gpo status` le lit.
//
// Une ligne par triplet, remplacée : c'est l'état présent qui compte, pas
// l'histoire — elle est au journal.
var tableConflitsDDL = `CREATE TABLE IF NOT EXISTS gpo_conflict (
	computeur_id VARCHAR(255) NOT NULL,
	scope        VARCHAR(16)  NOT NULL,
	target_user  VARCHAR(255) NOT NULL DEFAULT '',
	detail       TEXT         NOT NULL,
	seen_at      DATETIME     NOT NULL,
	PRIMARY KEY (computeur_id, scope, target_user)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

// ConflitGPO : les conflits d'une portée, tels que la dernière résolution les a vus.
type ConflitGPO struct {
	ComputeurID string
	Scope       string
	TargetUser  string
	Detail      string
	SeenAt      time.Time
}

// RangerConflits remplace les conflits d'une portée ; un détail vide les
// efface. Rend vrai si le détail a changé — l'appelant ne journalise qu'alors,
// et non à chaque cycle de chaque machine.
func RangerConflits(db *sql.DB, computeurID, scope, targetUser, detail string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("base indisponible")
	}
	var avant string
	err := db.QueryRow(`SELECT detail FROM gpo_conflict WHERE computeur_id = ? AND scope = ? AND target_user = ?`,
		computeurID, scope, targetUser).Scan(&avant)
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("lecture des conflits de %s : %w", computeurID, err)
	}
	if detail == "" {
		if err == sql.ErrNoRows {
			return false, nil
		}
		if _, err := db.Exec(`DELETE FROM gpo_conflict WHERE computeur_id = ? AND scope = ? AND target_user = ?`,
			computeurID, scope, targetUser); err != nil {
			return false, fmt.Errorf("effacement des conflits de %s : %w", computeurID, err)
		}
		return true, nil
	}
	if _, err := db.Exec(`INSERT INTO gpo_conflict (computeur_id, scope, target_user, detail, seen_at)
		VALUES (?, ?, ?, ?, NOW())
		ON DUPLICATE KEY UPDATE detail = VALUES(detail), seen_at = NOW()`,
		computeurID, scope, targetUser, detail); err != nil {
		return false, fmt.Errorf("écriture des conflits de %s : %w", computeurID, err)
	}
	return avant != detail, nil
}

// ConflitsDeLaMachine : les conflits d'une machine, toutes portées.
func ConflitsDeLaMachine(db *sql.DB, computeurID string) ([]ConflitGPO, error) {
	return lireConflits(db, `WHERE computeur_id = ?`, computeurID)
}

// ConflitsDuParc : tous les conflits rangés, pour la vue du parc.
func ConflitsDuParc(db *sql.DB) ([]ConflitGPO, error) {
	return lireConflits(db, ``)
}

func lireConflits(db *sql.DB, filtre string, args ...any) ([]ConflitGPO, error) {
	if db == nil {
		return nil, fmt.Errorf("base indisponible")
	}
	rows, err := db.Query(`SELECT computeur_id, scope, target_user, detail, seen_at FROM gpo_conflict `+
		filtre+` ORDER BY computeur_id, scope, target_user`, args...)
	if err != nil {
		return nil, fmt.Errorf("lecture des conflits entre GPO : %w", err)
	}
	defer rows.Close()
	var out []ConflitGPO
	for rows.Next() {
		var c ConflitGPO
		if err := rows.Scan(&c.ComputeurID, &c.Scope, &c.TargetUser, &c.Detail, &c.SeenAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
