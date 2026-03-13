package display

import (
	"fmt"
	"strings"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// DisplayUserPublicKeys formate et retourne les clés publiques d'un utilisateur
func DisplayUserPublicKeys(username string, pubKeys []storage.PublicKey) string {
	if len(pubKeys) == 0 {
		return fmt.Sprintf(">> -No public key found for user %s", username)
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf(">> Public keys for user %s:\n", username))
	for _, key := range pubKeys {
		builder.WriteString(fmt.Sprintf("ID: %d, Label: %s, CreatedAt: %s\nKey: %s\n\n", key.ID, key.Label, key.CreatedAt, key.Key))
	}
	result := builder.String()
	logs.Write_Log("INFO", fmt.Sprintf("Displayed %d public keys for user %s", len(pubKeys), username))
	return result
}
