package serveur

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

// generateServiceRandomID tire l'identifiant de machine d'un service enrôlé.
//
// Même forme que celui d'un agent — alphanumérique puis date — pour qu'un
// identifiant reste lisible de la même façon d'un bout à l'autre du produit.
// La fonction est dupliquée plutôt qu'importée depuis ducky-network/new_client :
// ce paquet importe déjà l'authentification, et l'inverse formerait un cycle.
func generateServiceRandomID(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("génération d'identifiant : %w", err)
		}
		result[i] = charset[index.Int64()]
	}
	return string(result) + "-" + time.Now().Format("02-01-2006"), nil
}
