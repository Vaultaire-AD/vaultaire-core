package guardprotected

import (
	"fmt"
	"vaultaire/core/logs"
)

// refuseProtected journalise la tentative et retourne l'erreur à remonter.
//
// Le niveau SECURITY est volontaire : une tentative de suppression du compte
// d'amorçage est soit une erreur de manipulation qu'il faut pouvoir retracer,
// soit une tentative de verrouiller l'administrateur légitime dehors.
func refuseProtected(kind, name, operation string) error {
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"protection: tentative de %s sur le %s protégé %q — refusée", operation, kind, name))
	return fmt.Errorf("le %s %q est protégé : %s est impossible", kind, name, operation)
}
