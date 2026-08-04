package database

import (
	"regexp"
)

// identifierRe décrit la forme acceptée d'un identifiant.
//
// Lettres, chiffres, point, tiret, souligné, arobase — de quoi écrire
// « admin », « admin@vaultaire.fr », « compta.vaultaire.fr », « poste-042 ».
// La longueur est bornée pour éviter qu'une valeur démesurée ne se propage dans
// des journaux ou des noms de fichiers.
var identifierRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,128}$`)
