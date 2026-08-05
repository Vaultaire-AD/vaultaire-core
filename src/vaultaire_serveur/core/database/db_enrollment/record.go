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
	ExpiresAt  sql.NullTime
	CreatedBy  string
	CreatedAt  time.Time
	RevokedBy  sql.NullString
	RevokedAt  sql.NullTime
}

// Unlimited : les deux bornes acceptent une valeur « sans limite ».
//
//	MaxUses == 0        quota illimité
//	ExpiresAt invalide  pas d'expiration
//
// Une clé sans limite ne s'éteint que par révocation. C'est utile pour une
// chaîne de déploiement qui recrée des services sans intervention humaine, et
// c'est exactement pour cela que la révocation reste le seul moyen de l'arrêter :
// il faut un geste explicite, pas l'écoulement du temps.
func (r Record) UnlimitedUses() bool { return r.MaxUses == 0 }
func (r Record) NeverExpires() bool  { return !r.ExpiresAt.Valid }

// Usable indique si la clé peut encore servir à cet instant.
func (r Record) Usable(now time.Time) bool {
	if r.RevokedAt.Valid {
		return false
	}
	if !r.UnlimitedUses() && r.UsedCount >= r.MaxUses {
		return false
	}
	if !r.NeverExpires() && !now.Before(r.ExpiresAt.Time) {
		return false
	}
	return true
}

// Status résume l'état de la clé pour l'affichage.
func (r Record) Status(now time.Time) string {
	switch {
	case r.RevokedAt.Valid:
		return "révoquée"
	case !r.UnlimitedUses() && r.UsedCount >= r.MaxUses:
		return "épuisée"
	case !r.NeverExpires() && !now.Before(r.ExpiresAt.Time):
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
