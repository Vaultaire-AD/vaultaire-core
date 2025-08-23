package keymanagement

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseRSAPublicKeyFromPEM convertit une clé publique PEM en *rsa.PublicKey
func ParseRSAPublicKeyFromPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("clé PEM invalide")
	}

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
		return nil, fmt.Errorf("erreur parse clé publique: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("clé non RSA")
	}

	return rsaPub, nil
}
