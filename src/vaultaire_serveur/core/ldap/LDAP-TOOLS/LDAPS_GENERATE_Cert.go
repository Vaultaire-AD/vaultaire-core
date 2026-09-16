package ldaptools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func FileEmpty(filename string) bool {
	info, err := os.Stat(filename)
	return err != nil || info.Size() == 0

}

func GenerateSelfSignedCert(certPath, keyPath string) error {
	// Assure-toi que le répertoire existe
	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"YNOV Labs"},
			CommonName:   "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(2, 0, 0),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Génération du certificat
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Écriture du certificat
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}

	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// Écriture de la clé privée
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	log.Println("🔐 Certificat et clé générés.")
	return nil
}

// GenerateSelfSignedCertPEM génère le certificat LDAPS auto-signé, avec les
// noms alternatifs détectés sur l'hôte et ceux déclarés en configuration.
//
// Conserve sa signature d'origine : c'est le point d'entrée du serveur LDAPS.
func GenerateSelfSignedCertPEM() (certPEM string, keyPEM string, err error) {
	return GenerateLDAPSCertPEM(BuildSANSet(ConfiguredDNSNames(), ConfiguredIPs()))
}

// GenerateLDAPSCertPEM génère un certificat auto-signé couvrant un jeu de SAN.
//
// # Ce qui a changé, et pourquoi
//
// La version précédente écrivait :
//
//	Subject:     pkix.Name{CommonName: "localhost"},
//	IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
//
// Aucun SAN DNS. Or depuis JDK 9, la vérification du nom d'hôte côté Java
// IGNORE le CommonName et exige un SAN : tout client Java se connectant par un
// nom — Keycloak au premier chef — échouait à la poignée de main, sous un
// message qui ne désigne pas le certificat.
//
// # RSA 2048 conservé
//
// ECDSA P-256 serait plus rapide et aussi sûr, mais certains connecteurs LDAP
// anciens ne l'acceptent pas — et un annuaire se raccorde justement à des
// clients qu'on ne choisit pas. Le coût est payé une fois, à la génération.
//
// # Validité de deux ans
//
// Le renouvellement d'un certificat auto-signé est un geste manuel : chaque
// client qui l'a importé doit réimporter. Deux ans est un compromis entre la
// corvée et l'exposition. Une expiration produit le MÊME message d'erreur que
// l'absence de SAN, d'où la trace de la date dans le journal au démarrage.
func GenerateLDAPSCertPEM(sans SANSet) (certPEM string, keyPEM string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Numéro de série tiré au hasard, et non dérivé de l'horloge.
	//
	// RFC 5280 §4.1.2.2 : le couple (émetteur, numéro de série) doit être
	// unique. Deux serveurs générant leur certificat à la même seconde — ce que
	// fait un déploiement automatisé — produisaient le même numéro sous le même
	// émetteur « YNOV Labs ». Certains magasins de confiance rejettent alors le
	// second comme un doublon du premier.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}

	// Le CommonName reprend le premier nom DNS. Il n'est plus consulté par
	// aucun client à jour, mais il reste ce qu'affichent les outils de
	// diagnostic — et un « localhost » affiché sur un certificat de production
	// envoie chercher la panne au mauvais endroit.
	commonName := "vaultaire-ldaps"
	if len(sans.DNSNames) > 0 {
		commonName = sans.DNSNames[0]
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Vaultaire"},
			CommonName:   commonName,
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().AddDate(2, 0, 0),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		// IsCA : le certificat est son propre émetteur. Un magasin de confiance
		// Java refuse d'installer comme ancre de confiance un certificat qui
		// n'est pas marqué CA — c'est pourtant exactement ce qu'on demande à
		// l'administrateur de faire avec un auto-signé.
		IsCA:        true,
		DNSNames:    sans.DNSNames,
		IPAddresses: sans.IPs,
	}

	// NotBefore reculé de cinq minutes : les horloges d'un serveur et de son
	// client ne sont jamais exactement d'accord, et un certificat « pas encore
	// valide » échoue de la même façon qu'un certificat expiré.

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	var certBuf, keyBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", err
	}
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return "", "", err
	}
	return certBuf.String(), keyBuf.String(), nil
}
