package keydecodeencode

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func EncryptMessageWithClientPublic(message string, clientSoftwareID string) ([]byte, error) {
	clt_publicKey, err := database.Get_Client_Software_PublicKey(database.GetDatabase(), clientSoftwareID)
	if err != nil {
		logs.Write_Log("ERROR", "Error during th recover of the client software pubkey:"+err.Error())
		fmt.Println("Erreur lors de la recuperation de la clé :" + err.Error())
	}
	// block, _ := pem.Decode([]byte(usr_publicKey))
	// if block == nil || block.Type != "RSA PUBLIC KEY" {
	// 	return nil, fmt.Errorf("erreur lors du décodage de la clé publique")
	// }
	block, _ := pem.Decode([]byte(clt_publicKey))
	if block == nil || (block.Type != "RSA PUBLIC KEY" && block.Type != "PUBLIC KEY") {
		logs.Write_Log("ERROR", "error decoding public key")
		return nil, fmt.Errorf("error decoding public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logs.Write_Log("ERROR", "error parsing public key")
		return nil, fmt.Errorf("error parsing public key : %v", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		logs.Write_Log("ERROR", "The rsa key is not a valid rsa key")
		return nil, fmt.Errorf("The rsa key is not a valid rsa key")
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, []byte(message))
	if err != nil {
		logs.Write_Log("ERROR", "error during the encryption: "+err.Error())
		return nil, fmt.Errorf("error during the encryption: %v", err)
	}
	return ciphertext, nil
}
