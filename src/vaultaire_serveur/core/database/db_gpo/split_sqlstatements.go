package dbgpo

import (
	"strings"
)

// splitSQLStatements découpe le fichier de peuplement en instructions.
//
// Le découpage respecte les chaînes entre apostrophes (les contenus de
// définitions en contiennent, avec des séquences \n échappées) : un point-virgule
// à l'intérieur d'une chaîne ne termine pas l'instruction.
func splitSQLStatements(script string) []string {
	script = lineCommentRe.ReplaceAllString(script, "")

	var statements []string
	var current strings.Builder
	inString := false

	for i := 0; i < len(script); i++ {
		c := script[i]
		if inString {
			current.WriteByte(c)
			switch c {
			case '\\':
				// Séquence échappée : le caractère suivant est littéral, y compris
				// une apostrophe. Sans ça, '\'' fermerait la chaîne à tort.
				if i+1 < len(script) {
					i++
					current.WriteByte(script[i])
				}
			case '\'':
				inString = false
			}
			continue
		}
		switch c {
		case '\'':
			inString = true
			current.WriteByte(c)
		case ';':
			if s := strings.TrimSpace(current.String()); s != "" {
				statements = append(statements, s)
			}
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	if s := strings.TrimSpace(current.String()); s != "" {
		statements = append(statements, s)
	}
	return statements
}
