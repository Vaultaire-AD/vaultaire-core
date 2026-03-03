package keymanagement

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"vaultaire/serveur/logs"
)

func ClientWritePEMKey(filename string, key *rsa.PrivateKey) error {
	// Ouvrir ou créer un fichier avec des permissions spécifiques (0600)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the save of the private key: "+err.Error())
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
		}
	}()

	// Sérialiser la clé privée en format PEM
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}

	// Encoder la clé privée en PEM et l'écrire dans le fichier
	return pem.Encode(file, privBlock)
}

func ClientWritePEMKeyPublic(filename string, pubkey *rsa.PublicKey) error {
	// _, err := os.Create(filename)
	// if err != nil {
	// 	logs.WriteLog("error", "Erreur lors de la save de la clé publique creation du fchier:"+err.Error())
	// 	return err
	// }
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the save of the public key: "+err.Error())
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
		}
	}()

	pubBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the convertion Marshal of the public key:"+err.Error())
		return err
	}
	pubBlock := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes}

	return pem.Encode(file, pubBlock)
}
