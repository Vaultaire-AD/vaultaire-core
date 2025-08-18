package keymanagement

import (
	"fmt"
	"os"
	"path/filepath"
	store "vaultaire_client/storage"
)

func GetServeurPublicKey() string {
	publicKeyPath := filepath.Join(store.KeyPath, "serveurpublickey.pem")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		fmt.Println("Erreur lors de la lecture de la clé publique du serveur:", err)
		return "err"
	}
	return string(publicKeyBytes)
}
