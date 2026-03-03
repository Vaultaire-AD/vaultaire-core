package database

import (
	"vaultaire/serveur/logs"
	"fmt"
	"regexp"
	"runtime"
)

// Fonction anti-SQL injection
func SanitizeInput(inputs ...string) error {
	// Définition des caractères dangereux dans une expression régulière
	unsafeChars := `['";\n\r\t\0\x1a]` // Déplace "-" au début ou à la fin
	re := regexp.MustCompile(unsafeChars)

	// Récupération de l'appelant (la fonction qui a appelé SanitizeInput)
	pc, _, _, _ := runtime.Caller(1) // Niveau 1 = fonction appelante directe
	functionSource := runtime.FuncForPC(pc).Name()

	// Vérification de chaque input
	for _, input := range inputs {
		if re.MatchString(input) {
			// Log avec le nom de la fonction appelante
			logs.WriteLog("SQL_Injection", fmt.Sprintf("Appel depuis %s", functionSource))
			return fmt.Errorf("injection SQL détectée : caractères dangereux trouvés dans l'entrée : %s", input)
		}
	}
	// Aucune injection détectée
	return nil
}
