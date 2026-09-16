package dbgpo

// seedStatement est une instruction de peuplement et sa table cible.
type seedStatement struct {
	Table string
	SQL   string
}
