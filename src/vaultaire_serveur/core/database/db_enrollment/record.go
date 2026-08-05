package dbenrollment

import (
	"database/sql"
	"time"
)

// Record est une clé d'enrôlement telle qu'elle est stockée.
//
// Le secret n'y figure pas et n'y figurera jamais : seul son condensat est en
// base, et il n'est pas exposé ici non plus — rien dans l'application n'a besoin
// de le lire, seulement de le comparer.
type Record struct {
	ID         int
	Label      string
	ClientType string
	MaxUses    int
	UsedCount  int
	ExpiresAt  time.Time
	CreatedBy  string
	CreatedAt  time.Time
	RevokedBy  sql.NullString
	RevokedAt  sql.NullTime
}

// Usable indique si la clé peut encore servir à cet instant.
func (r Record) Usable(now time.Time) bool {
	return !r.RevokedAt.Valid && r.UsedCount < r.MaxUses && now.Before(r.ExpiresAt)
}

// Status résume l'état de la clé pour l'affichage.
func (r Record) Status(now time.Time) string {
	switch {
	case r.RevokedAt.Valid:
		return "révoquée"
	case r.UsedCount >= r.MaxUses:
		return "épuisée"
	case !now.Before(r.ExpiresAt):
		return "expirée"
	default:
		return "active"
	}
}

// Use est une consommation de clé.
type Use struct {
	ComputeurID string
	ClientType  string
	SourceIP    sql.NullString
	UsedAt      time.Time
}
