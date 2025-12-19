package keymanagement

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func Generate_Serveur_Key_Pair(keyName string) (privateKeyPath, publicKeyPath string, err error) {
	privateKeyPath = storage.Client_Conf_path + ".ssh/" + keyName + "_private.pem"
	publicKeyPath = storage.Client_Conf_path + ".ssh/" + keyName + "_public.pem"
	if _, err := os.Stat(privateKeyPath); !os.IsNotExist(err) {
		fmt.Println("private key already exist", privateKeyPath)
		return privateKeyPath, publicKeyPath, nil
	}

	if _, err := os.Stat(publicKeyPath); !os.IsNotExist(err) {
		fmt.Println("Public key already exist", publicKeyPath)
		return privateKeyPath, publicKeyPath, nil
	}

	privateKey, publicKey, err := GenerateKeyRSA(4096)
	if err != nil {
		logs.Write_Log("ERROR", "Error generateRSAKEY:"+err.Error())
		return privateKeyPath, publicKeyPath, err
	}

	err = SavePEMKey(privateKeyPath, privateKey)
	if err != nil {
		fmt.Println("Error during the save of the pubkey:", err)
		logs.Write_Log("ERROR", "Error during the save of the pubkey:"+err.Error())
		return privateKeyPath, publicKeyPath, err
	}

	err = SavePEMKeyPublic(publicKeyPath, publicKey)
	if err != nil {
		fmt.Println("Error during the save of the pubkey:", err)
		logs.Write_Log("ERROR", "Error during the save of the pubkey:"+err.Error())
		return privateKeyPath, publicKeyPath, err
	}

	fmt.Println("Key pair generated with succes.")
	return privateKeyPath, publicKeyPath, nil
}

func GenerateKeyRSA(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		logs.Write_Log("ERROR", "Erreur generateRSAKEY:"+err.Error())
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

func SavePEMKey(filename string, key *rsa.PrivateKey) error {
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

func SavePEMKeyPublic(filename string, pubkey *rsa.PublicKey) error {
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
