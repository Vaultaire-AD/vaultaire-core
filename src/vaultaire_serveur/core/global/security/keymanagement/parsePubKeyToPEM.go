package keymanagement

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ParseRSAPublicKeyFromPEM convertit une clé publique PEM en *rsa.PublicKey
func ParseRSAPublicKeyFromPEM(pubKeyStr string) (*rsa.PublicKey, error) {
	// Essayer PEM d'abord
	block, _ := pem.Decode([]byte(pubKeyStr))
	if block != nil {
		var pub interface{}
		var err error
		switch block.Type {
		case "PUBLIC KEY":
			pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		case "RSA PUBLIC KEY":
			pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		default:
			return nil, fmt.Errorf("type de clé non supporté: %s", block.Type)
		}
		if err != nil {
			return nil, err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("clé non RSA")
		}
		return rsaPub, nil
	}

	// Sinon essayer OpenSSH
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		return nil, fmt.Errorf("erreur parse clé OpenSSH: %w", err)
	}
	if cryptoPub, ok := key.(ssh.CryptoPublicKey); ok {
		if rsaPub, ok := cryptoPub.CryptoPublicKey().(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
	}
	return nil, errors.New("clé publique non RSA")
}
