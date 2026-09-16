package dbgpo

import (
	"regexp"
)

// definitionNameRe borne les noms de définition : ce nom est écrit tel quel dans
// les paramètres JSON d'un module, et recherché par motif lors de la suppression.
// Le restreindre garantit que les deux opérations restent exactes.
var definitionNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)
