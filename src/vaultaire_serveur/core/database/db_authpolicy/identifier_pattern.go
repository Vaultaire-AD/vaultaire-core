package dbauthpolicy

import (
	"regexp"
)

// identifierPattern borne les noms de table et de colonne acceptés par
// ensureColumn.
//
// Ces noms ne peuvent pas être passés en paramètre de requête préparée : MySQL
// n'accepte de placeholder que pour des valeurs, pas pour des identifiants. La
// concaténation est donc inévitable, et c'est ce motif qui la rend sûre. Tous
// les appelants actuels passent des constantes du code — mais un futur appelant
// qui passerait une chaîne venue d'ailleurs se heurterait ici plutôt qu'à une
// injection.
var identifierPattern = regexp.MustCompile(`^[a-z_]{1,64}$`)
