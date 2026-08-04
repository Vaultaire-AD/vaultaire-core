package dbgpo

import (
	"regexp"
)

var (
	// lineCommentRe retire les commentaires SQL en fin ou en début de ligne.
	lineCommentRe = regexp.MustCompile(`(?m)^\s*--.*$`)
	// insertTargetRe extrait la table visée par une instruction INSERT.
	insertTargetRe = regexp.MustCompile(`(?is)^\s*INSERT\s+(?:IGNORE\s+)?INTO\s+([A-Za-z0-9_]+)`)
)
