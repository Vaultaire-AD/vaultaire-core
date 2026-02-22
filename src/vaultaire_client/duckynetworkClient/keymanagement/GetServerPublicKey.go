package keymanagement

import (
	"fmt"
	"os"
	"path/filepath"
	"vaultaire_client/logs"
	store "vaultaire_client/storage"
)

func GetServeurPublicKey() string {
	publicKeyPath := filepath.Join(store.KeyPath, "serveurpublickey.pem")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture de la clé publique du serveur: %v", err))
		return "err"
	}
	return string(publicKeyBytes)
}
