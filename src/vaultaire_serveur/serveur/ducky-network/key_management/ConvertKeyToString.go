package keymanagement

import (
	"DUCKY/serveur/logs"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
)

func Convert_Public_Key_To_String(publicKey *rsa.PublicKey) string {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the convertion of the pubkey:"+err.Error())
		log.Fatalf("Error during the convertion of the pubkey: %v", err)
	}

	// Encoder en format PEM
	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Convertir en chaîne
	pubKeyStr := string(pubKeyPem)
	return pubKeyStr
}

func Convert_Private_Key_To_String(privateKey *rsa.PrivateKey) string {
	prvKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the convertion of the pubkey:"+err.Error())
		log.Fatalf("Error during the convertion of the pubkey: %v", err)
	}

	// Encoder en format PEM
	prvKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: prvKeyBytes,
	})

	// Convertir en chaîne
	prvKeyStr := string(prvKeyPem)
	return prvKeyStr
}
