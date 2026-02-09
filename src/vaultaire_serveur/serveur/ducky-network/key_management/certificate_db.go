package keymanagement

import (
	"vaultaire/serveur/database/db-certificates"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Noms standards pour les certificats/clés système
const (
	ServerMainKeyName      = "server_main"
	ServerLoginClientKeyName = "server_login_client"
	WebServerCertName      = "web_server"
	APIServerCertName      = "api_server"
	LDAPSServerCertName   = "ldaps_server"
)

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

	// Vérifier si le certificat existe déjà
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

	logs.Write_Log("INFO", fmt.Sprintf("keymanagement: key pair '%s' saved to database", name))
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

	logs.Write_Log("INFO", fmt.Sprintf("keymanagement: certificate '%s' saved to database", name))
	return nil
}

// SaveSSHKeyToDB enregistre une paire de clés SSH (contenu brut privé + public) en BDD.
func SaveSSHKeyToDB(name, description, privContent, pubContent string) error {
	_, err := dbcertificates.GetCertificateByName(name)
	if err == nil {
		return fmt.Errorf("certificat '%s' existe déjà", name)
	}
	desc := &description
	if description == "" {
		desc = nil
	}
	_, err = dbcertificates.CreateCertificate(name, "ssh_key", nil, &privContent, &pubContent, desc)
	if err != nil {
		return fmt.Errorf("sauvegarde clé SSH en BDD: %v", err)
	}
	logs.Write_Log("INFO", fmt.Sprintf("keymanagement: SSH key '%s' saved to database", name))
	return nil
}

// EnsureLoginClientKeyFiles écrit les clés SSH "login client" depuis la BDD vers les chemins fichiers
// pour que ssh -i /path fonctionne. À appeler au démarrage si le certificat existe en BDD.
func EnsureLoginClientKeyFiles() error {
	cert, err := dbcertificates.GetCertificateByName(ServerLoginClientKeyName)
	if err != nil {
		return err
	}
	if cert.PrivateKeyData == nil || cert.PublicKeyData == nil {
		return fmt.Errorf("certificat %s incomplet (clé privée ou publique manquante)", ServerLoginClientKeyName)
	}
	dir := storage.Client_Conf_path + ".ssh"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("création répertoire .ssh: %v", err)
	}
	if err := os.WriteFile(storage.PrivateKeyforlogintoclient, []byte(*cert.PrivateKeyData), 0600); err != nil {
		return fmt.Errorf("écriture clé privée login client: %v", err)
	}
	pubPath := storage.PublicKeyforlogintoclient
	if err := os.WriteFile(pubPath, []byte(*cert.PublicKeyData), 0600); err != nil {
		return fmt.Errorf("écriture clé publique login client: %v", err)
	}
	logs.Write_Log("INFO", "keymanagement: login client SSH keys exported from database to files")
	return nil
}

// GetLoginClientPrivateKeyPath retourne le chemin du fichier de clé privée SSH login client.
// La clé est chargée depuis la BDD et écrite dans un fichier temporaire si nécessaire.
// Cette fonction garantit que le fichier existe avant de retourner son chemin.
func GetLoginClientPrivateKeyPath() (string, error) {
	// S'assurer que les fichiers existent (depuis la BDD)
	if err := EnsureLoginClientKeyFiles(); err != nil {
		return "", fmt.Errorf("impossible de préparer la clé SSH login client: %v", err)
	}
	return storage.PrivateKeyforlogintoclient, nil
}

// EnsureClientSoftwareKeyFiles écrit les clés d'un client software depuis la BDD vers des fichiers temporaires
// pour le transfert SFTP. Retourne les chemins des fichiers créés.
func EnsureClientSoftwareKeyFiles(computeurID string) (privateKeyPath, publicKeyPath string, err error) {
	keyName := fmt.Sprintf("client_software_%s", computeurID)
	cert, err := dbcertificates.GetCertificateByName(keyName)
	if err != nil {
		return "", "", fmt.Errorf("clés pour client software %s non trouvées en BDD: %v", computeurID, err)
	}
	if cert.PrivateKeyData == nil || cert.PublicKeyData == nil {
		return "", "", fmt.Errorf("certificat %s incomplet (clé privée ou publique manquante)", keyName)
	}

	// Créer le répertoire si nécessaire
	dir := storage.Client_Conf_path + "/clientsoftware/" + computeurID
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("création répertoire client software: %v", err)
	}

	// Écrire les fichiers temporaires
	privateKeyPath = filepath.Join(dir, "private_key.pem")
	publicKeyPath = filepath.Join(dir, "public_key.pem")

	if err := os.WriteFile(privateKeyPath, []byte(*cert.PrivateKeyData), 0600); err != nil {
		return "", "", fmt.Errorf("écriture clé privée client software: %v", err)
	}
	if err := os.WriteFile(publicKeyPath, []byte(*cert.PublicKeyData), 0600); err != nil {
		return "", "", fmt.Errorf("écriture clé publique client software: %v", err)
	}

	logs.Write_Log("DEBUG", fmt.Sprintf("keymanagement: client software %s keys exported to %s", computeurID, dir))
	return privateKeyPath, publicKeyPath, nil
}
