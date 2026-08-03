package keyencodedecode

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func EncryptMessageWithPublic(publicKeyStr string, message string) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("erreur lors du décodage de la clé publique")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("erreur lors du parsing de la clé publique : %v", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("la clé n'est pas une clé rsa valide")
	}
	// OAEP — voir oaep_params.go.
	//
	// C'est le chiffrement des trames envoyées au serveur avant l'établissement
	// de la clé de session : celles-là mêmes que le serveur déchiffrait avec sa
	// clé privée, et qui constituaient l'oracle de bourrage tant qu'on était en
	// PKCS#1 v1.5.
	ciphertext, err := rsa.EncryptOAEP(OAEPHash(), rand.Reader, rsaPublicKey, []byte(message), OAEPLabel)
	if err != nil {
		return nil, fmt.Errorf("erreur lors du chiffrement (%d octets, maximum %d) : %v",
			len(message), MaxOAEPPayload(rsaPublicKey.Size()), err)
	}
	return ciphertext, nil
}
