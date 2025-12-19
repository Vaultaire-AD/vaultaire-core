package keymanagement

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
)

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

func Generate_Serveur_Key_Pair() error {

	if _, err := os.Stat(storage.PrivateKeyPath); !os.IsNotExist(err) {
		fmt.Println("private key already exist", storage.PrivateKeyPath)
		return nil
	}

	if _, err := os.Stat(storage.PublicKeyPath); !os.IsNotExist(err) {
		fmt.Println("Public key already exist", storage.PublicKeyPath)
		return nil
	}

	privateKey, publicKey, err := GenerateKeyRSA(4096)
	if err != nil {
		logs.Write_Log("ERROR", "Error generateRSAKEY:"+err.Error())
		return err
	}

	err = SavePEMKey(storage.PrivateKeyPath, privateKey)
	if err != nil {
		fmt.Println("Error during the save of the pubkey:", err)
		logs.Write_Log("ERROR", "Error during the save of the pubkey:"+err.Error())
		return err
	}

	err = SavePEMKeyPublic(storage.PublicKeyPath, publicKey)
	if err != nil {
		fmt.Println("Error during the save of the pubkey:", err)
		logs.Write_Log("ERROR", "Error during the save of the pubkey:"+err.Error())
		return err
	}

	fmt.Println("Key pair generated with succes.")
	return nil
}

func Generate_SSH_Key_For_Login_Client() error {
	// Vérifier si les clés existent déjà
	if _, err := os.Stat(storage.PrivateKeyforlogintoclient); err == nil {
		if _, err := os.Stat(storage.PrivateKeyforlogintoclient); err == nil {
			fmt.Println("🔁 Les clés SSH existent déjà, génération ignorée.")
			return nil
		}
	}

	// Créer le dossier s’il n’existe pas
	if err := os.MkdirAll("/opt/vaultaire/.ssh", 0700); err != nil {
		logs.Write_Log("ERROR", "Erreur lors de la création du dossier .ssh : "+err.Error())
		return fmt.Errorf("❌ Impossible de créer le dossier .ssh : %v", err)
	}

	// Générer la clé avec ssh-keygen
	cmd := exec.Command(
		"ssh-keygen",
		"-t", "rsa",
		"-b", "4096",
		"-f", storage.PrivateKeyforlogintoclient,
		"-N", "", // pas de passphrase
		"-C", "vaultaire_login_client",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	logs.Write_Log("INFO", "🔐 Génération de la paire de clés RSA avec ssh-keygen...")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("❌ Erreur ssh-keygen : %v\n%s", err, stderr.String())
	}

	logs.Write_Log("INFO", "✅ Clé SSH générée avec succès :")
	logs.Write_Log("INFO", "   🔑 Privée : "+storage.PrivateKeyforlogintoclient)
	logs.Write_Log("INFO", "   🗝️ Publique : "+storage.PublicKeyforlogintoclient)

	return nil
}
