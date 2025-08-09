package keymanagement

import (
	store "vaultaire_client/storage"
	"fmt"
	"os"
	"path/filepath"
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
