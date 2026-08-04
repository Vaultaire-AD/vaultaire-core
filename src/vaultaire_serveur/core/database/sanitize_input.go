package database

import (
	"fmt"
	"vaultaire/core/logs"
)

// SanitizeInput refuse les caractères dangereux dans du texte libre.
//
// Ne remplace pas les requêtes préparées et n'a jamais prétendu le faire : c'est
// une seconde barrière, utile là où une valeur ne peut pas être passée en
// paramètre (nom de colonne, par exemple).
func SanitizeInput(inputs ...string) error {
	functionSource := callerName()

	for _, input := range inputs {
		if unsafeChars.MatchString(input) {
			logs.WriteLog("SQL_Injection", fmt.Sprintf("Appel depuis %s", functionSource))
			return fmt.Errorf("injection SQL détectée : caractères dangereux trouvés dans l'entrée : %s", input)
		}
	}
	return nil
}
