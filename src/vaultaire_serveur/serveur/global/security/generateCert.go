package security

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"bytes"
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
	defer certOut.Close()
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeCertSave, "security: certificate write failed: "+err.Error())
		return err
	}
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeCertSave, "security: private key write failed: "+err.Error())
		return err
	}
	return nil
}

// GenerateSelfSignedCertPEM génère un certificat X.509 auto-signé et sa clé privée, retournés en PEM (sans fichier).
// Utilisé pour sauvegarder en BDD puis servir TLS depuis la BDD.
func GenerateSelfSignedCertPEM() (certPEM string, keyPEM string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
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
		return "", "", err
	}

	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}

	var certBuf, keyBuf bytes.Buffer
	if err := pem.Encode(&certBuf, certBlock); err != nil {
		return "", "", err
	}
	if err := pem.Encode(&keyBuf, keyBlock); err != nil {
		return "", "", err
	}
	return certBuf.String(), keyBuf.String(), nil
}
