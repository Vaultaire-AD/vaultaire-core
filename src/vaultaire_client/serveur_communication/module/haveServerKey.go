package module

import (
	"os"
	"path/filepath"
	"vaultaire_client/storage"
)

func HaveServeurKey() bool {
	serveurKeyPath := filepath.Join(storage.KeyPath, "serveurpublickey.pem")
	_, privateErr := os.Stat(serveurKeyPath)
	return !os.IsNotExist(privateErr)
}
