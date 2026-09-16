package dbrevocation

import (
	"database/sql"
	"time"
	"vaultaire/core/revocation"
)

// Record est un ordre tel qu'il est stocké, avec sa trace d'audit.
type Record struct {
	ID       int
	Username string
	Mode     revocation.Mode
	Reason   revocation.Reason
	IssuedBy string
	IssuedAt time.Time
	LiftedBy string
	LiftedAt sql.NullTime
	Pending  int // machines restant à traiter
	Total    int // machines visées
}
