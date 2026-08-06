package keymanagement

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"os"
	"path/filepath"
)

func GetServeurPublicKey() string {
	publicKeyPath := filepath.Join(storage.KeyPath, "serveurpublickey.pem")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture de la clé publique du serveur: %v", err))
		return "err"
	}
	return string(publicKeyBytes)
}
