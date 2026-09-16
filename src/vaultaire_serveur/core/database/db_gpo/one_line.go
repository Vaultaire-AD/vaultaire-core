package dbgpo

import (
	"strings"
)

// oneLine condense un contenu multiligne pour le journal d'audit.
func oneLine(payload string) string {
	compact := strings.Join(strings.Fields(strings.ReplaceAll(payload, "\n", " ; ")), " ")
	if len(compact) > 200 {
		return compact[:200] + "…"
	}
	return compact
}
