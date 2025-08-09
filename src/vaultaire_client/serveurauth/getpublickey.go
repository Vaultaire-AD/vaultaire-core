package serveurauth

import (
	store "vaultaire_client/storage"
	"fmt"
	"os"
	"path/filepath"
)

func GetPublicKey() string {
	publicKeyPath := filepath.Join(store.KeyPath, "public.pem")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		fmt.Println("Erreur lors de la lecture de la clé publique :", err)
		return "err"
	}
	return string(publicKeyBytes)
}
