package database

import (
	"fmt"
	"strings"
	"vaultaire/core/logs"
)

// SanitizeIdentifier n'accepte qu'un identifiant bien formé.
//
// À utiliser pour tout ce qui NOMME une entité. Pour du texte libre — mot de
// passe, description, contenu de fichier déployé, motif d'expression
// régulière — utiliser SanitizeInput : cette fonction-ci les refuserait tous.
func SanitizeIdentifier(inputs ...string) error {
	functionSource := callerName()

	for _, input := range inputs {
		// La valeur vide est traitée à part : le message « identifiant vide »
		// est autrement plus parlant qu'un rejet de forme, et c'est une erreur
		// d'appel fréquente (champ de formulaire non rempli).
		if strings.TrimSpace(input) == "" {
			logs.WriteLog("SQL_Injection", fmt.Sprintf("Identifiant vide depuis %s", functionSource))
			return fmt.Errorf("identifiant vide")
		}
		if !identifierRe.MatchString(input) {
			logs.WriteLog("SQL_Injection", fmt.Sprintf(
				"Identifiant malformé %q depuis %s", input, functionSource))
			return fmt.Errorf(
				"identifiant invalide %q : lettres, chiffres, point, tiret, souligné et arobase uniquement (128 caractères max)",
				input)
		}
	}
	return nil
}
