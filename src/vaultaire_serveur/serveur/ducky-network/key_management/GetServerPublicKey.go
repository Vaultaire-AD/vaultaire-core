package keymanagement

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"fmt"
	"os"
)

func GetPublicKey() string {

	publicKeyBytes, err := os.ReadFile(storage.PublicKeyPath)
	if err != nil {
		fmt.Println("Error Critique Fail server Private Key :", err)
		logs.Write_Log("CRITICAL", "Error Critique Fail server Private Key:"+err.Error())
		panic(0)
	}
	return string(publicKeyBytes)
}
