package keymanagement

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"os"
)

func Get_Client_Private_Key() string {
	publicKeyPath := storage.CheminDansKeyPath("private_key.pem")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture de la clé privée du client: %v", err))
		return "err"
	}
	return string(publicKeyBytes)
}
