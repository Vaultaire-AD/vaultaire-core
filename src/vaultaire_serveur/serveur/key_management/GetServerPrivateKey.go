package keymanagement

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"fmt"
	"os"
)

func GetPrivateKey() string {

	publicKeyBytes, err := os.ReadFile(storage.PrivateKeyPath)
	if err != nil {
		fmt.Println("Error during pubkey reading :", err)
		logs.Write_Log("CRITICAL", "Error during pubkey reading : "+err.Error())
		panic(0)
	}
	return string(publicKeyBytes)
}
