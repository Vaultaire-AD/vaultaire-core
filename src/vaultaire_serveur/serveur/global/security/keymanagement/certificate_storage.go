package keymanagement

import (
	"vaultaire/serveur/database/db-certificates"
	"vaultaire/serveur/logs"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// SaveKeyPairToDB sauvegarde une paire de clés RSA dans la base de données
func SaveKeyPairToDB(name, certType, description string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) error {
	// Convertir la clé privée en PEM
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	var privBuf bytes.Buffer
	if err := pem.Encode(&privBuf, privBlock); err != nil {
		return fmt.Errorf("erreur encodage clé privée: %v", err)
	}
	privKeyPEM := privBuf.String()

	// Convertir la clé publique en PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("erreur marshalling clé publique: %v", err)
	}
	pubBlock := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes}
	var pubBuf bytes.Buffer
	if err := pem.Encode(&pubBuf, pubBlock); err != nil {
		return fmt.Errorf("erreur encodage clé publique: %v", err)
	}
	pubKeyPEM := pubBuf.String()

	_, err = dbcertificates.GetCertificateByName(name)
	if err == nil {
		return fmt.Errorf("certificat '%s' existe déjà", name)
	}

	// Créer le certificat dans la BDD
	desc := &description
	if description == "" {
		desc = nil
	}
	_, err = dbcertificates.CreateCertificate(name, certType, nil, &privKeyPEM, &pubKeyPEM, desc)
	if err != nil {
		return fmt.Errorf("erreur sauvegarde certificat en BDD: %v", err)
	}

	logs.Write_Log("INFO", "keymanagement: key pair '"+name+"' saved to database")
	return nil
}

// GetKeyPairFromDB récupère une paire de clés RSA depuis la base de données
func GetKeyPairFromDB(name string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	cert, err := dbcertificates.GetCertificateByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur récupération certificat '%s': %v", name, err)
	}

	if cert.PrivateKeyData == nil {
		return nil, nil, fmt.Errorf("certificat '%s' n'a pas de clé privée", name)
	}
	if cert.PublicKeyData == nil {
		return nil, nil, fmt.Errorf("certificat '%s' n'a pas de clé publique", name)
	}

	// Parser la clé privée
	privBlock, _ := pem.Decode([]byte(*cert.PrivateKeyData))
	if privBlock == nil {
		return nil, nil, fmt.Errorf("erreur décodage PEM clé privée")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur parsing clé privée: %v", err)
	}

	// Parser la clé publique
	pubBlock, _ := pem.Decode([]byte(*cert.PublicKeyData))
	if pubBlock == nil {
		return nil, nil, fmt.Errorf("erreur décodage PEM clé publique")
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur parsing clé publique: %v", err)
	}
	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("la clé publique n'est pas une clé RSA")
	}

	return privateKey, publicKey, nil
}

// GetPrivateKeyPEMFromDB récupère la clé privée en format PEM depuis la BDD
func GetPrivateKeyPEMFromDB(name string) (string, error) {
	cert, err := dbcertificates.GetCertificateByName(name)
	if err != nil {
		return "", fmt.Errorf("erreur récupération certificat '%s': %v", name, err)
	}

	if cert.PrivateKeyData == nil {
		return "", fmt.Errorf("certificat '%s' n'a pas de clé privée", name)
	}

	return *cert.PrivateKeyData, nil
}

// GetPublicKeyPEMFromDB récupère la clé publique en format PEM depuis la BDD
func GetPublicKeyPEMFromDB(name string) (string, error) {
	cert, err := dbcertificates.GetCertificateByName(name)
	if err != nil {
		return "", fmt.Errorf("erreur récupération certificat '%s': %v", name, err)
	}

	if cert.PublicKeyData == nil {
		return "", fmt.Errorf("certificat '%s' n'a pas de clé publique", name)
	}

	return *cert.PublicKeyData, nil
}

// SaveCertificateToDB sauvegarde un certificat TLS (X.509) dans la base de données
func SaveCertificateToDB(name, certType, description string, certPEM, privKeyPEM string) error {
	// Vérifier si le certificat existe déjà
	_, err := dbcertificates.GetCertificateByName(name)
	if err == nil {
		return fmt.Errorf("certificat '%s' existe déjà", name)
	}

	desc := &description
	if description == "" {
		desc = nil
	}
	certData := &certPEM
	privKeyData := &privKeyPEM

	_, err = dbcertificates.CreateCertificate(name, certType, certData, privKeyData, nil, desc)
	if err != nil {
		return fmt.Errorf("erreur sauvegarde certificat en BDD: %v", err)
	}

	logs.Write_Log("INFO", "keymanagement: certificate '"+name+"' saved to database")
	return nil
}

// GetCertificatePEMFromDB récupère un certificat TLS depuis la BDD
func GetCertificatePEMFromDB(name string) (certPEM string, privKeyPEM string, err error) {
	cert, err := dbcertificates.GetCertificateByName(name)
	if err != nil {
		return "", "", fmt.Errorf("erreur récupération certificat '%s': %v", name, err)
	}

	if cert.CertificateData == nil {
		return "", "", fmt.Errorf("certificat '%s' n'a pas de données de certificat", name)
	}
	if cert.PrivateKeyData == nil {
		return "", "", fmt.Errorf("certificat '%s' n'a pas de clé privée", name)
	}

	return *cert.CertificateData, *cert.PrivateKeyData, nil
}
