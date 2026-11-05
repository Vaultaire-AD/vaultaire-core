package certimporte

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// paireTest fabrique un certificat de serveur signé par une petite autorité.
func paireTest(t *testing.T, cn string, debut, fin time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	cleCA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	modeleCA := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA de test"},
		NotBefore: debut.Add(-time.Hour), NotAfter: fin.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	derCA, err := x509.CreateCertificate(rand.Reader, modeleCA, modeleCA, &cleCA.PublicKey, cleCA)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(derCA)

	cle, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	modele := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{cn}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: debut, NotAfter: fin,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, modele, ca, &cle.PublicKey, cleCA)
	if err != nil {
		t.Fatal(err)
	}
	derCle, _ := x509.MarshalECPrivateKey(cle)
	// Chaîne : serveur puis autorité, comme le tls.crt de cert-manager.
	certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCA})...)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derCle})
	return
}

func ecrire(t *testing.T, dir string, cert, cle []byte) (string, string) {
	t.Helper()
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(c, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k, cle, 0o600); err != nil {
		t.Fatal(err)
	}
	return c, k
}

type journalTest struct {
	mu     sync.Mutex
	lignes []string
}

func (j *journalTest) brancher(t *testing.T) {
	ancien := Journal
	Journal = func(n, m string) {
		j.mu.Lock()
		defer j.mu.Unlock()
		j.lignes = append(j.lignes, n+" "+m)
	}
	t.Cleanup(func() { Journal = ancien })
}

// compteSur : compte sous verrou, pour les tests où la surveillance écrit.
func (j *journalTest) compteSur(niveau string) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.compte(niveau)
}

func (j *journalTest) compte(niveau string) int {
	n := 0
	for _, l := range j.lignes {
		if strings.HasPrefix(l, niveau+" ") {
			n++
		}
	}
	return n
}

func servi(t *testing.T, s *Source) string {
	t.Helper()
	c, err := s.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	return c.Leaf.Subject.CommonName
}

func TestChargerEtRecharger(t *testing.T) {
	var j journalTest
	j.brancher(t)
	dir := t.TempDir()
	maintenant := time.Now()
	c1, k1 := paireTest(t, "ldap-v1.acme.lan", maintenant.Add(-time.Hour), maintenant.Add(90*24*time.Hour))
	cf, kf := ecrire(t, dir, c1, k1)

	s := Nouvelle(ServiceLDAPS, cf, kf)
	horloge := maintenant
	s.maintenant = func() time.Time { return horloge }
	if err := s.Charger(); err != nil {
		t.Fatal(err)
	}
	if got := servi(t, s); got != "ldap-v1.acme.lan" {
		t.Fatalf("servi %q", got)
	}

	// Renouvellement : rien avant l'intervalle, le nouveau après.
	c2, k2 := paireTest(t, "ldap-v2.acme.lan", maintenant.Add(-time.Hour), maintenant.Add(90*24*time.Hour))
	ecrire(t, dir, c2, k2)
	if got := servi(t, s); got != "ldap-v1.acme.lan" {
		t.Fatalf("relu avant l'intervalle : %q", got)
	}
	horloge = horloge.Add(Intervalle + time.Second)
	if got := servi(t, s); got != "ldap-v2.acme.lan" {
		t.Fatalf("pas rechargé : %q", got)
	}
	if j.compte("INFO") != 1 {
		t.Fatalf("journal : %v", j.lignes)
	}
	if !strings.Contains(s.CertPEM(), "BEGIN CERTIFICATE") {
		t.Fatal("CertPEM vide")
	}
}

func TestPaireIncoherenteGardeLAncienne(t *testing.T) {
	var j journalTest
	j.brancher(t)
	dir := t.TempDir()
	maintenant := time.Now()
	c1, k1 := paireTest(t, "web-v1", maintenant.Add(-time.Hour), maintenant.Add(time.Hour*24))
	cf, kf := ecrire(t, dir, c1, k1)
	s := Nouvelle(ServiceWeb, cf, kf)
	horloge := maintenant
	s.maintenant = func() time.Time { return horloge }
	if err := s.Charger(); err != nil {
		t.Fatal(err)
	}

	// Nouveau certificat, ANCIENNE clé : refusé.
	c2, _ := paireTest(t, "web-v2", maintenant.Add(-time.Hour), maintenant.Add(time.Hour*24))
	ecrire(t, dir, c2, k1)
	horloge = horloge.Add(Intervalle + time.Second)
	if got := servi(t, s); got != "web-v1" {
		t.Fatalf("paire incohérente servie : %q", got)
	}
	if j.compte("ERROR") != 0 {
		t.Fatal("une première lecture incohérente ne doit pas encore être signalée")
	}
	// Relu 2 s plus tard, toujours incohérent : signalé, une seule fois.
	horloge = horloge.Add(3 * time.Second)
	servi(t, s)
	horloge = horloge.Add(Intervalle + time.Second)
	servi(t, s)
	if j.compte("ERROR") != 1 {
		t.Fatalf("attendu un refus au journal : %v", j.lignes)
	}
	if s.Etat().DerniereErreur == "" {
		t.Fatal("l'état doit porter l'erreur")
	}
	if got := servi(t, s); got != "web-v1" {
		t.Fatalf("servi %q", got)
	}
}

func TestChargerRefuse(t *testing.T) {
	maintenant := time.Now()
	cas := map[string]func(dir string) (string, string){
		"expiré": func(dir string) (string, string) {
			c, k := paireTest(t, "x", maintenant.Add(-48*time.Hour), maintenant.Add(-time.Hour))
			return ecrire(t, dir, c, k)
		},
		"pas encore valide": func(dir string) (string, string) {
			c, k := paireTest(t, "x", maintenant.Add(time.Hour), maintenant.Add(48*time.Hour))
			return ecrire(t, dir, c, k)
		},
		"inversés": func(dir string) (string, string) {
			c, k := paireTest(t, "x", maintenant.Add(-time.Hour), maintenant.Add(time.Hour))
			return ecrire(t, dir, k, c)
		},
		"absent": func(dir string) (string, string) {
			return filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key")
		},
		"vide": func(dir string) (string, string) {
			return ecrire(t, dir, []byte("\n"), []byte("\n"))
		},
	}
	for nom, prep := range cas {
		t.Run(nom, func(t *testing.T) {
			cf, kf := prep(t.TempDir())
			if err := Nouvelle(ServiceAPI, cf, kf).Charger(); err == nil {
				t.Fatal("accepté")
			}
		})
	}
}

func TestConfigurer(t *testing.T) {
	dir := t.TempDir()
	c, k := paireTest(t, "api", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cf, kf := ecrire(t, dir, c, k)

	if err := Configurer(ServiceAPI, "", ""); err != nil || Pour(ServiceAPI) != nil {
		t.Fatal("rien déclaré : rien d'importé")
	}
	if err := Configurer(ServiceAPI, cf, ""); err == nil {
		t.Fatal("certificat sans clé accepté")
	}
	if err := Configurer(ServiceAPI, "", kf); err == nil {
		t.Fatal("clé sans certificat acceptée")
	}
	if err := Configurer(ServiceAPI, cf, kf); err != nil || Pour(ServiceAPI) == nil {
		t.Fatalf("paire valide refusée : %v", err)
	}
	// Retirer la déclaration retire l'import.
	if err := Configurer(ServiceAPI, "", ""); err != nil || Pour(ServiceAPI) != nil {
		t.Fatal("import resté enregistré")
	}
}

// Un Secret Kubernetes monté : tls.crt → ..data/tls.crt, ..data → ..v1/.
// La mise à jour remplace le lien ..data d'un seul geste.
func TestSecretKubernetes(t *testing.T) {
	var j journalTest
	j.brancher(t)
	dir := t.TempDir()
	maintenant := time.Now()
	poserVersion := func(nom, cn string) {
		v := filepath.Join(dir, nom)
		if err := os.Mkdir(v, 0o755); err != nil {
			t.Fatal(err)
		}
		c, k := paireTest(t, cn, maintenant.Add(-time.Hour), maintenant.Add(24*time.Hour))
		ecrire(t, v, c, k)
		tmp := filepath.Join(dir, "..data_tmp")
		if err := os.Symlink(nom, tmp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	poserVersion("..v1", "k8s-v1")
	for _, f := range []string{"tls.crt", "tls.key"} {
		if err := os.Symlink(filepath.Join("..data", f), filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	s := Nouvelle(ServiceLDAPS, filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	horloge := maintenant
	s.maintenant = func() time.Time { return horloge }
	if err := s.Charger(); err != nil {
		t.Fatal(err)
	}
	poserVersion("..v2", "k8s-v2")
	horloge = horloge.Add(Intervalle + time.Second)
	if got := servi(t, s); got != "k8s-v2" {
		t.Fatalf("servi %q", got)
	}
}

// Sans aucune poignée de main, la surveillance relit, sert et signale.
func TestSurveillanceSansTrafic(t *testing.T) {
	var j journalTest
	j.brancher(t)
	ancien := Intervalle
	Intervalle = 20 * time.Millisecond
	t.Cleanup(func() { _ = Configurer(ServiceAPI, "", ""); Intervalle = ancien })

	dir := t.TempDir()
	maintenant := time.Now()
	c1, k1 := paireTest(t, "api-v1", maintenant.Add(-time.Hour), maintenant.Add(24*time.Hour))
	cf, kf := ecrire(t, dir, c1, k1)
	if err := Configurer(ServiceAPI, cf, kf); err != nil {
		t.Fatal(err)
	}
	s := Pour(ServiceAPI)
	avant := s.CertPEM()

	// Paire incohérente : jamais servie, et dite au journal sans trafic.
	c2, k2 := paireTest(t, "api-v2", maintenant.Add(-time.Hour), maintenant.Add(24*time.Hour))
	ecrire(t, dir, c2, k1)
	attendre(t, func() bool { return j.compteSur("ERROR") == 1 })
	if s.CertPEM() != avant {
		t.Fatal("paire incohérente servie")
	}

	// Paire cohérente : servie sans trafic.
	ecrire(t, dir, c2, k2)
	attendre(t, func() bool { return s.CertPEM() != avant })
}

func attendre(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("délai dépassé")
}
