package dbgpo

import (
	"fmt"
	"strings"
)

// loadSeedStatements lit et découpe le script de peuplement embarqué.
func loadSeedStatements() ([]seedStatement, error) {
	raw, err := seedFS.ReadFile(seedFilePath)
	if err != nil {
		return nil, fmt.Errorf("script de peuplement GPO illisible : %v", err)
	}

	var out []seedStatement
	for _, stmt := range splitSQLStatements(string(raw)) {
		match := insertTargetRe.FindStringSubmatch(stmt)
		if match == nil {
			return nil, fmt.Errorf("instruction de peuplement non reconnue (INSERT attendu) : %.80s…", stmt)
		}
		out = append(out, seedStatement{Table: strings.ToLower(match[1]), SQL: stmt})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("script de peuplement GPO vide")
	}
	return out, nil
}
