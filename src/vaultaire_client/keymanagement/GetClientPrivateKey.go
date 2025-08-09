package keymanagement

import (
	store "vaultaire_client/storage"
	"fmt"
	"os"
	"path/filepath"
)

func Get_Client_Private_Key() string {
	publicKeyPath := filepath.Join(store.KeyPath, "private_key.pem")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		fmt.Println("Erreur lors de la lecture de la clé publique du serveur:", err)
		return "err"
	}
	return string(publicKeyBytes)
}
