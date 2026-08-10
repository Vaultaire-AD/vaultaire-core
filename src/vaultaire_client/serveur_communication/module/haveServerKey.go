package module

import (
	"duckynetworkclient/V1/duckynetwork/storage"
	"os"
	"path/filepath"
)

func HaveServeurKey() bool {
	serveurKeyPath := filepath.Join(storage.KeyPath, "serveurpublickey.pem")
	_, privateErr := os.Stat(serveurKeyPath)
	return !os.IsNotExist(privateErr)
}
