package dbrevocation

// IsActive dit si l'ordre est toujours en vigueur.
func (r Record) IsActive() bool { return !r.LiftedAt.Valid }
