package dbrevocation

import (
	"database/sql"
	"vaultaire/core/revocation"
)

// TargetRecord est l'état d'un ordre pour une machine.
type TargetRecord struct {
	ComputeurID string
	Status      revocation.TargetStatus
	LastAttempt sql.NullTime
	Detail      string
}
