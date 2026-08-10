package serveurauth

import (
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"os"
)

func GetPublicKey() string {
	publicKeyPath := storage.CheminDansKeyPath("public.pem")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		fmt.Println("Erreur lors de la lecture de la clé publique :", err)
		return "err"
	}
	return string(publicKeyBytes)
}
