package configuration_file

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vaultaire/core/global/security/certimporte"
	"vaultaire/core/storage"
)

func ecrirePaire(t *testing.T, dir string) (string, string) {
	t.Helper()
	cle, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	modele := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "ldap.acme.lan"},
		DNSNames: []string{"ldap.acme.lan"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, modele, modele, &cle.PublicKey, cle)
	if err != nil {
		t.Fatal(err)
	}
	derCle, _ := x509.MarshalECPrivateKey(cle)
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	_ = os.WriteFile(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derCle}), 0o600)
	return c, k
}

// Variables posées → certificat importé ; une moitié de paire → démarrage refusé.
func TestCertificatsImportesParLEnvironnement(t *testing.T) {
	c, k := ecrirePaire(t, t.TempDir())
	t.Cleanup(func() {
		storage.Ldaps_TLS_CertFile, storage.Ldaps_TLS_KeyFile = "", ""
		storage.Web_TLS_CertFile, storage.Web_TLS_KeyFile = "", ""
		_ = ConfigurerCertificatsImportes()
	})

	env := map[string]string{"VAULTAIRE_LDAPS_TLS_CERT_FILE": c, "VAULTAIRE_LDAPS_TLS_KEY_FILE": k}
	if err := AppliquerEnvironnement(func(n string) (string, bool) { v, ok := env[n]; return v, ok }); err != nil {
		t.Fatal(err)
	}
	if err := ConfigurerCertificatsImportes(); err != nil {
		t.Fatal(err)
	}
	if certimporte.Pour(certimporte.ServiceLDAPS) == nil {
		t.Fatal("LDAPS non importé")
	}
	if certimporte.Pour(certimporte.ServiceWeb) != nil {
		t.Fatal("web importé sans déclaration")
	}

	storage.Web_TLS_CertFile = c
	err := ConfigurerCertificatsImportes()
	if err == nil || !strings.Contains(err.Error(), "website.web_tls_cert_file") || !strings.Contains(err.Error(), "sans clé") {
		t.Fatalf("moitié de paire acceptée : %v", err)
	}
}
