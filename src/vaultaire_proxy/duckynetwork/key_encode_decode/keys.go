package keyencodedecode

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Lecture, écriture et génération de clés RSA.

// ParsePublicKey lit une clé publique PEM.
func ParsePublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("bloc PEM absent dans la clé publique")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clé publique illisible : %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("clé publique non RSA")
	}
	return pub, nil
}

// ParsePrivateKey lit une clé privée PEM.
//
// Accepte PKCS#8 et PKCS#1 : le core écrit du PKCS#8, mais une clé produite à la
// main avec openssl est souvent en PKCS#1. Refuser cette forme ferait échouer un
// déploiement sur un détail sans importance.
func ParsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("bloc PEM absent dans la clé privée")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("clé privée non RSA")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clé privée illisible : %w", err)
	}
	return key, nil
}

// MarshalPublicKey sérialise au format attendu par le core.
func MarshalPublicKey(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// MarshalPrivateKey sérialise en PKCS#8, comme le core.
func MarshalPrivateKey(priv *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// GenerateKeyPair tire une paire RSA-4096, comme le core.
//
// La génération prend de l'ordre de la seconde : acceptable, elle n'a lieu qu'à
// l'enrôlement.
func GenerateKeyPair() (privatePEM, publicPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", fmt.Errorf("génération de la paire : %w", err)
	}
	if privatePEM, err = MarshalPrivateKey(key); err != nil {
		return "", "", err
	}
	if publicPEM, err = MarshalPublicKey(&key.PublicKey); err != nil {
		return "", "", err
	}
	return privatePEM, publicPEM, nil
}
