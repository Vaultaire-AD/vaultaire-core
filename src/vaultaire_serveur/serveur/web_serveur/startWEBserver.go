package webserveur

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"
)

var templates = template.Must(template.ParseFiles("./web_packet/sso_WEB_page/templates/sso_login.html"))

func StartWebServer() {
	path := storage.Client_Conf_path + ".ssh/"
	certFile := path + "server_cert.pem"
	keyFile := path + "server_key.pem"
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		if err := generateSelfSignedCert(certFile, keyFile); err != nil {
			log.Fatal("Erreur génération certificat:", err)
		}
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./web_packet/sso_WEB_page/static"))))
	http.HandleFunc("/", LoginPageHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/profil", ProfilHandler)
	server_Port := strconv.Itoa(storage.Website_Port)
	fmt.Println("Serveur HTTPS démarré sur https://0.0.0.0:" + server_Port)
	log.Fatal(http.ListenAndServeTLS(":"+server_Port, certFile, keyFile, nil))
}

// --- Certificat auto-signé
func generateSelfSignedCert(certFile, keyFile string) error {
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
		logs.Write_Log("ERROR", "Erreur lors de l'écriture du certificat: "+err.Error())
		return err
	}
	// Écrire key.pem
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de l'écriture de la clé privée: "+err.Error())
		return err
	}
	return nil
}
