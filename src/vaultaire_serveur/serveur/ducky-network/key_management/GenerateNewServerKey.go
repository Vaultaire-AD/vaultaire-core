package keymanagement

import (
	"vaultaire/serveur/logs"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"golang.org/x/crypto/ssh"
)

func GenerateKeyRSA(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeNetKey, "keymanagement: RSA key generation failed: "+err.Error())
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}


func Generate_Serveur_Key_Pair() error {
	_, err := GetPrivateKeyPEMFromDB(ServerMainKeyName)
	if err == nil {
		logs.Write_Log("INFO", "keymanagement: server key pair already present in database (server_main)")
		return nil
	}

	privateKey, publicKey, err := GenerateKeyRSA(4096)
	if err != nil {
		return err
	}

	if errSave := SaveKeyPairToDB(ServerMainKeyName, "rsa_keypair", "Clé principale serveur Ducky", privateKey, publicKey); errSave != nil {
		logs.Write_LogCode("ERROR", logs.CodeCertSave, "keymanagement: save server key pair failed: "+errSave.Error())
		return errSave
	}
	logs.Write_Log("INFO", "keymanagement: server key pair generated and saved (server_main)")
	return nil
}

// GenerateSSHKeyInOpenSSHFormat génère une clé SSH RSA et la retourne en format OpenSSH (pour ssh -i)
func GenerateSSHKeyInOpenSSHFormat() (privateKeyOpenSSH string, publicKeyOpenSSH string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", fmt.Errorf("génération clé RSA: %v", err)
	}

	// Formater la clé privée en OpenSSH (PEM avec header "OPENSSH PRIVATE KEY" ou format traditionnel)
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	var privBuf bytes.Buffer
	if err := pem.Encode(&privBuf, privBlock); err != nil {
		return "", "", fmt.Errorf("encodage clé privée: %v", err)
	}
	privateKeyOpenSSH = privBuf.String()

	// Formater la clé publique en format OpenSSH (ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... comment)
	publicKeySSH, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("création clé publique SSH: %v", err)
	}
	publicKeyOpenSSH = string(ssh.MarshalAuthorizedKey(publicKeySSH))
	// Retirer le \n final
	publicKeyOpenSSH = strings.TrimRight(publicKeyOpenSSH, "\n")

	return privateKeyOpenSSH, publicKeyOpenSSH, nil
}

func Generate_SSH_Key_For_Login_Client() error {
	if err := EnsureLoginClientKeyFiles(); err == nil {
		logs.Write_Log("INFO", "keymanagement: login client SSH keys loaded from database")
		return nil
	}

	privContent, pubContent, err := GenerateSSHKeyInOpenSSHFormat()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeCertSave, "keymanagement: SSH key generation failed: "+err.Error())
		return fmt.Errorf("génération clé SSH: %v", err)
	}

	if errSave := SaveSSHKeyToDB(ServerLoginClientKeyName, "Clé SSH pour login client (create -c -join)", privContent, pubContent); errSave != nil {
		logs.Write_LogCode("ERROR", logs.CodeCertSave, "keymanagement: SSH key save to database failed: "+errSave.Error())
		return fmt.Errorf("sauvegarde clé SSH en BDD: %v", errSave)
	}

	logs.Write_Log("INFO", "keymanagement: login client SSH key generated and saved (server_login_client)")
	return nil
}
