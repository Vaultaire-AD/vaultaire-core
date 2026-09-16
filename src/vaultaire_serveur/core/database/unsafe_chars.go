package database

import (
	"regexp"
)

// unsafeChars sont les caractères refusés partout, y compris dans le texte
// libre : guillemets, point-virgule et caractères de contrôle.
var unsafeChars = regexp.MustCompile(`['";\n\r\t\x00\x1a]`)
