package dbgpo

import (
	"embed"
)

//go:embed seed/gpo_seed.sql
var seedFS embed.FS
