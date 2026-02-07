package security

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func GenerateSelfSignedCert(keyPath, certName string) (certPath string, err error) {
	path := storage.Client_Conf_path + ".ssh/"
	certPath = path + certName + ".pem"
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := createSelfSignedCert(certPath, keyPath); err != nil {
			log.Fatal("Erreur génération certificat:", err)
		}
	} else {
		fmt.Println("INFO: Certificat déjà existant, pas de génération nécessaire.")
	}
	return certPath, nil
}

// --- Certificat auto-signé
func createSelfSignedCert(certFile, keyFile string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SSO Vaultaire"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Écrire cert.pem
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := certOut.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de l'écriture du certificat: "+err.Error())
		return err
	}
	// Écrire key.pem
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := keyOut.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de l'écriture de la clé privée: "+err.Error())
		return err
	}
	return nil
}
