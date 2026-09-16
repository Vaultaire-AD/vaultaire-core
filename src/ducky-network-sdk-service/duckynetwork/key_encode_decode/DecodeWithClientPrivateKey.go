package keyencodedecode

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func DecryptMessageWithPrivate(privateKeyStr string, ciphertext []byte) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("error decoding private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("error parsing private key: %v", err)
	}

	// OAEP — voir oaep_params.go. Le serveur chiffre avec les mêmes paramètres ;
	// un écart ferait échouer ce déchiffrement sans autre indice qu'une erreur
	// de bourrage.
	plaintext, err := rsa.DecryptOAEP(OAEPHash(), rand.Reader, privateKey, ciphertext, OAEPLabel)
	if err != nil {
		return "", fmt.Errorf("error decrypting: %v", err)
	}

	return string(plaintext), nil
}
