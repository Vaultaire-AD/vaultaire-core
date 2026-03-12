package keymanagement

import (
	"fmt"
	"os"
	"path/filepath"
	"vaultaire_client/logs"
	store "vaultaire_client/storage"
)

func Get_Client_Private_Key() string {
	publicKeyPath := filepath.Join(store.KeyPath, "private_key.pem")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture de la clé privée du client: %v", err))
		return "err"
	}
	return string(publicKeyBytes)
}
