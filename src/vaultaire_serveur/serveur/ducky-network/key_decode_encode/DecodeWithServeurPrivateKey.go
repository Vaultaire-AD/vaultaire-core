package keydecodeencode

import (
	"DUCKY/serveur/logs"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func DecryptMessageWithPrivate(privateKeyStr string, ciphertext []byte) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		logs.Write_Log("CRITICAL", "Erreur decoding private key")
		return "", fmt.Errorf("error decoding private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logs.Write_Log("CRITICAL", "Erreur Parsing"+err.Error())
		return "", fmt.Errorf("error parsing private key: %v", err)
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		logs.Write_Log("CRITICAL", "Erreur "+err.Error())
		return "", fmt.Errorf("error decrypting: %v", err)
	}

	return string(plaintext), nil
}
