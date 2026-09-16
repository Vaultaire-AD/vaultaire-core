package security

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
	"vaultaire/core/storage"
)

// Le test central de ce fichier n'inspecte pas les champs du certificat : il le
// soumet à la vérification de crypto/x509, celle-là même qu'exécute tout client
// TLS.
//
// La distinction est délibérée. Vérifier « DNSNames contient localhost » teste
// que le code fait ce que le code fait. Vérifier « x509 accepte ce certificat
// pour ce nom » teste ce qui nous intéresse réellement, et attrape du même coup
// les erreurs auxquelles on n'a pas pensé.

func poserMachineDeTest(t *testing.T, hostname string, adresses []net.Addr) {
	t.Helper()
	vH, vA := osHostname, netInterfaceAddrs
	vDNS, vIPs := storage.Web_TLS_DNSNames, storage.Web_TLS_IPs

	osHostname = func() (string, error) { return hostname, nil }
	netInterfaceAddrs = func() ([]net.Addr, error) { return adresses, nil }

	t.Cleanup(func() {
		osHostname, netInterfaceAddrs = vH, vA
		storage.Web_TLS_DNSNames, storage.Web_TLS_IPs = vDNS, vIPs
	})
}

func reseau(cidr string) net.Addr {
	ip, bloc, _ := net.ParseCIDR(cidr)
	bloc.IP = ip
	return bloc
}

func analyser(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	bloc, _ := pem.Decode([]byte(certPEM))
	if bloc == nil {
		t.Fatal("PEM illisible")
	}
	cert, err := x509.ParseCertificate(bloc.Bytes)
	if err != nil {
		t.Fatalf("certificat illisible : %v", err)
	}
	return cert
}

// TestCertificatAccepteParUnClientTLS est LE test.
//
// Il reproduit la vérification d'un client : construire un magasin de confiance
// contenant le certificat, puis demander sa validation pour un nom donné. C'est
// exactement ce que fait un navigateur, curl, ou la bibliothèque TLS de Go.
//
// Sur l'ancien code — ni CommonName ni SAN — il échoue avec le message que les
// clients affichaient : « x509: certificate is not valid for any names ».
func TestCertificatAccepteParUnClientTLS(t *testing.T) {
	poserMachineDeTest(t, "vaultaire-ad.exemple.fr", []net.Addr{
		reseau("192.168.30.10/24"),
	})
	storage.Web_TLS_DNSNames = []string{"sso.exemple.fr"}
	storage.Web_TLS_IPs = nil

	certPEM, _, err := GenerateSelfSignedCertPEM()
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	cert := analyser(t, certPEM)

	magasin := x509.NewCertPool()
	magasin.AddCert(cert)

	nomsAttendus := []string{
		"vaultaire-ad.exemple.fr", // le nom de la machine
		"vaultaire-ad",            // sa forme courte
		"sso.exemple.fr",          // le nom déclaré en configuration
		"localhost",               // l'accès depuis la machine elle-même
		"192.168.30.10",           // l'adresse de son interface
		"127.0.0.1",
	}

	for _, nom := range nomsAttendus {
		t.Run(nom, func(t *testing.T) {
			_, err := cert.Verify(x509.VerifyOptions{
				DNSName:     nom,
				Roots:       magasin,
				CurrentTime: time.Now(),
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				t.Fatalf("un client TLS refuserait ce certificat pour %q : %v", nom, err)
			}
		})
	}
}

// TestCertificatRefusePourUnNomEtranger vérifie que le certificat ne couvre pas
// n'importe quoi.
//
// Un test qui ne contrôlerait que les acceptations passerait tout aussi bien
// sur un certificat qui accepterait TOUT — lequel ne protégerait de rien.
func TestCertificatRefusePourUnNomEtranger(t *testing.T) {
	poserMachineDeTest(t, "vaultaire-ad.exemple.fr", nil)
	storage.Web_TLS_DNSNames, storage.Web_TLS_IPs = nil, nil

	certPEM, _, err := GenerateSelfSignedCertPEM()
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	cert := analyser(t, certPEM)

	magasin := x509.NewCertPool()
	magasin.AddCert(cert)

	if _, err := cert.Verify(x509.VerifyOptions{
		DNSName: "attaquant.exemple.com",
		Roots:   magasin,
	}); err == nil {
		t.Fatal("le certificat est accepté pour un nom qui n'est pas le sien")
	}
}

// TestCommonNamePresent : le CN ne sert plus à valider, mais il est ce que les
// outils affichent. Vide, une liste de certificats devient illisible.
func TestCommonNamePresent(t *testing.T) {
	poserMachineDeTest(t, "vaultaire-ad.exemple.fr", nil)
	storage.Web_TLS_DNSNames, storage.Web_TLS_IPs = nil, nil

	certPEM, _, err := GenerateSelfSignedCertPEM()
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	cert := analyser(t, certPEM)

	if cert.Subject.CommonName == "" {
		t.Fatal("CommonName vide : « openssl x509 -subject » n'affichera aucun nom")
	}
	if cert.Subject.CommonName == "localhost" {
		t.Fatalf("CommonName « localhost » : tous les serveurs seraient indiscernables")
	}
	if cert.Subject.CommonName != "vaultaire-ad.exemple.fr" {
		t.Fatalf("CommonName %q, attendu le nom de la machine", cert.Subject.CommonName)
	}
}

// TestNumeroDeSerieSurBeaucoupDeBits.
//
// Le seuil est placé à 2^64. L'ancienne borne était 2^62, donc TOUT numéro
// tiré par l'ancien code échoue ici — ce qui est bien le but — tandis que la
// probabilité qu'un tirage sur 128 bits tombe sous 2^64 est de 2^-64.
func TestNumeroDeSerieSurBeaucoupDeBits(t *testing.T) {
	poserMachineDeTest(t, "vaultaire-ad", nil)
	storage.Web_TLS_DNSNames, storage.Web_TLS_IPs = nil, nil

	for i := 0; i < 20; i++ {
		certPEM, _, err := GenerateSelfSignedCertPEM()
		if err != nil {
			t.Fatalf("génération impossible : %v", err)
		}
		cert := analyser(t, certPEM)
		if cert.SerialNumber.BitLen() <= 64 {
			t.Fatalf("numéro de série sur %d bits : la RFC 5280 §4.1.2.2 en recommande au moins 64",
				cert.SerialNumber.BitLen())
		}
	}
}

// TestMargeAntidatage : sans elle, un client dont l'horloge retarde de quelques
// secondes rejette un certificat fraîchement émis.
func TestMargeAntidatage(t *testing.T) {
	poserMachineDeTest(t, "vaultaire-ad", nil)
	storage.Web_TLS_DNSNames, storage.Web_TLS_IPs = nil, nil

	certPEM, _, err := GenerateSelfSignedCertPEM()
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	cert := analyser(t, certPEM)

	if !cert.NotBefore.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("NotBefore à %v : une horloge en retard d'une minute rejetterait le certificat",
			cert.NotBefore)
	}
}

// TestAdresseDeLienLocalEcartee : fe80::/10 n'est routable de nulle part.
func TestAdresseDeLienLocalEcartee(t *testing.T) {
	poserMachineDeTest(t, "vaultaire-ad", []net.Addr{
		reseau("192.168.30.10/24"),
		reseau("fe80::1/64"),
	})
	storage.Web_TLS_DNSNames, storage.Web_TLS_IPs = nil, nil

	certPEM, _, err := GenerateSelfSignedCertPEM()
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	cert := analyser(t, certPEM)

	for _, ip := range cert.IPAddresses {
		if ip.IsLinkLocalUnicast() {
			t.Fatalf("adresse de lien-local %v inscrite : elle ne joint le service de nulle part", ip)
		}
	}
}

// TestAdresseGlisseeParmiLesNoms : une IP écrite dans la liste des noms DNS
// doit être rangée du bon côté.
//
// Un SAN de type DNS contenant une adresse n'est comparé par aucun client. Sans
// ce rangement, l'administrateur voit son adresse dans la configuration, la
// voit dans le certificat, et le client la refuse quand même.
func TestAdresseGlisseeParmiLesNoms(t *testing.T) {
	poserMachineDeTest(t, "vaultaire-ad", nil)
	storage.Web_TLS_DNSNames = []string{"10.0.0.5"}
	storage.Web_TLS_IPs = nil

	certPEM, _, err := GenerateSelfSignedCertPEM()
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	cert := analyser(t, certPEM)

	for _, n := range cert.DNSNames {
		if n == "10.0.0.5" {
			t.Fatal("adresse inscrite parmi les DNSNames : aucun client ne l'y comparera")
		}
	}
	trouvee := false
	for _, ip := range cert.IPAddresses {
		if ip.String() == "10.0.0.5" {
			trouvee = true
		}
	}
	if !trouvee {
		t.Fatal("adresse perdue : ni dans les noms, ni dans les adresses")
	}
}
