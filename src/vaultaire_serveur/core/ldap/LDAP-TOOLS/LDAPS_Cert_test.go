package ldaptools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// Tests du certificat LDAPS.
//
// # Ce qu'ils protègent
//
// Un certificat sans SAN DNS produit, côté client Java, exactement ceci :
//
//	Error when trying to connect to LDAP: 'SSLHandshakeFailed'
//
// Rien dans ce message ne désigne le certificat, et rien côté serveur n'apparaît
// dans le journal : la poignée de main échoue chez le client. C'est donc un
// défaut qu'aucun test d'intégration ne rattrape et qu'aucun journal ne signale
// — seul un test sur la structure du certificat le voit.

// avecHoteFactice remplace la détection système le temps d'un test.
//
// Sans cela, le test mesurerait la machine de compilation : il passerait ici et
// échouerait ailleurs, ce qui est pire qu'un test absent.
func avecHoteFactice(t *testing.T, hostname string, adresses []net.Addr) {
	t.Helper()
	oldH, oldC, oldA := osHostname, netLookupCNAME, netInterfaceAddrs

	osHostname = func() (string, error) { return hostname, nil }
	netLookupCNAME = func(string) (string, error) { return hostname + ".interne.local.", nil }
	netInterfaceAddrs = func() ([]net.Addr, error) { return adresses, nil }

	t.Cleanup(func() { osHostname, netLookupCNAME, netInterfaceAddrs = oldH, oldC, oldA })
}

func ipnet(s string) net.Addr {
	ip, reseau, _ := net.ParseCIDR(s)
	reseau.IP = ip
	return reseau
}

// TestSANContientLesNomsConfigures : le nom déclaré en configuration DOIT s'y
// trouver.
//
// C'est le cas d'un déploiement conteneurisé : le nom d'hôte est un identifiant
// aléatoire et les clients utilisent le nom du service. La détection automatique
// ne peut pas le deviner.
func TestSANContientLesNomsConfigures(t *testing.T) {
	avecHoteFactice(t, "core-01", []net.Addr{ipnet("10.0.0.5/24")})

	sans := BuildSANSet([]string{"vaultaire-ad", "ldap.exemple.fr"}, []string{"192.168.1.10"})

	for _, attendu := range []string{"vaultaire-ad", "ldap.exemple.fr"} {
		if !contientNom(sans.DNSNames, attendu) {
			t.Errorf("nom configuré %q absent des SAN : %v", attendu, sans.DNSNames)
		}
	}
	if !contientIP(sans.IPs, net.ParseIP("192.168.1.10")) {
		t.Errorf("adresse configurée absente des SAN : %v", sans.IPs)
	}
}

// TestSANFusionneAuLieuDeRemplacer : déclarer un nom ne doit pas faire perdre
// ceux détectés.
//
// Sinon, déclarer le nom de service ferait perdre l'adresse locale par laquelle
// l'administrateur teste depuis la machine — et le diagnostic deviendrait une
// seconde panne.
func TestSANFusionneAuLieuDeRemplacer(t *testing.T) {
	avecHoteFactice(t, "core-01", []net.Addr{ipnet("10.0.0.5/24")})

	sans := BuildSANSet([]string{"vaultaire-ad"}, nil)

	if !contientNom(sans.DNSNames, "core-01") {
		t.Errorf("nom d'hôte détecté perdu : %v", sans.DNSNames)
	}
	if !contientIP(sans.IPs, net.ParseIP("10.0.0.5")) {
		t.Errorf("adresse d'interface détectée perdue : %v", sans.IPs)
	}
}

// TestSANContientToujoursLaBoucleLocale : localhost et 127.0.0.1, quoi qu'il
// arrive.
//
// C'est par là que passent les tests depuis la machine elle-même — `ldapsearch
// -H ldaps://localhost` est le premier réflexe de diagnostic.
func TestSANContientToujoursLaBoucleLocale(t *testing.T) {
	avecHoteFactice(t, "core-01", nil)

	sans := BuildSANSet(nil, nil)

	if !contientNom(sans.DNSNames, "localhost") {
		t.Errorf("localhost absent : %v", sans.DNSNames)
	}
	if !contientIP(sans.IPs, net.ParseIP("127.0.0.1")) {
		t.Errorf("127.0.0.1 absent : %v", sans.IPs)
	}
}

// TestSANRangeLesAdressesDansLaBonneListe : une IP écrite dans la liste des noms
// doit atterrir parmi les adresses, et réciproquement.
//
// Une IP rangée en SAN DNS n'est comparée par AUCUN client : elle serait
// silencieusement inerte, et le certificat aurait l'air complet.
func TestSANRangeLesAdressesDansLaBonneListe(t *testing.T) {
	avecHoteFactice(t, "core-01", nil)

	sans := BuildSANSet([]string{"10.1.2.3"}, []string{"ldap.exemple.fr"})

	if contientNom(sans.DNSNames, "10.1.2.3") {
		t.Error("une adresse IP rangée parmi les noms DNS n'est comparée par aucun client")
	}
	if !contientIP(sans.IPs, net.ParseIP("10.1.2.3")) {
		t.Errorf("adresse non récupérée : %v", sans.IPs)
	}
	if !contientNom(sans.DNSNames, "ldap.exemple.fr") {
		t.Errorf("nom mis dans la colonne des adresses non récupéré : %v", sans.DNSNames)
	}
}

// TestSANIgnoreLaBoucleLocaleDesInterfaces : la boucle locale est ajoutée
// explicitement, pas relevée — sinon elle dépendrait de l'état des interfaces.
func TestSANIgnoreLaBoucleLocaleDesInterfaces(t *testing.T) {
	avecHoteFactice(t, "core-01", []net.Addr{
		ipnet("127.0.0.1/8"),
		ipnet("169.254.1.1/16"), // lien-local : jamais joignable de l'extérieur
		ipnet("10.0.0.5/24"),
	})

	sans := BuildSANSet(nil, nil)

	if contientIP(sans.IPs, net.ParseIP("169.254.1.1")) {
		t.Error("une adresse lien-local n'a rien à faire dans un certificat de service")
	}
	if !contientIP(sans.IPs, net.ParseIP("10.0.0.5")) {
		t.Error("adresse routable perdue")
	}
}

// TestCertificatPorteDesSANDNS est LE test de non-régression du bogue Keycloak.
//
// Le certificat précédent portait `CommonName: "localhost"` et un unique SAN
// `127.0.0.1`. Depuis JDK 9, la vérification du nom d'hôte ignore le
// CommonName : sans SAN DNS, aucun client Java ne peut se connecter par un nom.
func TestCertificatPorteDesSANDNS(t *testing.T) {
	avecHoteFactice(t, "core-01", []net.Addr{ipnet("10.0.0.5/24")})

	certPEM, keyPEM, err := GenerateLDAPSCertPEM(BuildSANSet([]string{"vaultaire-ad"}, nil))
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	if keyPEM == "" {
		t.Fatal("clé privée vide")
	}

	cert := parseCert(t, certPEM)

	if len(cert.DNSNames) == 0 {
		t.Fatal("aucun SAN DNS : les clients Java refuseront la connexion")
	}
	if !contientNom(cert.DNSNames, "vaultaire-ad") {
		t.Errorf("SAN DNS = %v, « vaultaire-ad » manquant", cert.DNSNames)
	}
	if !contientIP(cert.IPAddresses, net.ParseIP("10.0.0.5")) {
		t.Errorf("SAN IP = %v, 10.0.0.5 manquant", cert.IPAddresses)
	}
}

// TestCertificatEstUtilisableCommeAncreDeConfiance : un auto-signé qu'on demande
// d'importer doit être marqué CA.
//
// Java refuse d'installer comme ancre de confiance un certificat dont
// BasicConstraints ne dit pas CA — or c'est exactement ce qu'on demande à
// l'administrateur de faire avec `keytool -importcert`.
func TestCertificatEstUtilisableCommeAncreDeConfiance(t *testing.T) {
	avecHoteFactice(t, "core-01", nil)

	certPEM, _, err := GenerateLDAPSCertPEM(BuildSANSet(nil, nil))
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	cert := parseCert(t, certPEM)

	if !cert.BasicConstraintsValid || !cert.IsCA {
		t.Error("certificat non marqué CA : keytool refusera de l'installer comme ancre de confiance")
	}
	var serverAuth bool
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		t.Error("ExtKeyUsage sans ServerAuth : le certificat ne vaut pas pour un serveur TLS")
	}
}

// TestNumeroDeSerieAleatoire : deux certificats générés d'affilée doivent
// différer.
//
// L'ancien numéro venait de `time.Now().UnixNano()`. Deux serveurs provisionnés
// par le même script produisaient le même couple (émetteur, numéro de série),
// que RFC 5280 §4.1.2.2 exige unique — certains magasins rejettent alors le
// second comme un doublon.
func TestNumeroDeSerieAleatoire(t *testing.T) {
	avecHoteFactice(t, "core-01", nil)
	sans := BuildSANSet(nil, nil)

	pem1, _, err1 := GenerateLDAPSCertPEM(sans)
	pem2, _, err2 := GenerateLDAPSCertPEM(sans)
	if err1 != nil || err2 != nil {
		t.Fatalf("génération impossible : %v %v", err1, err2)
	}

	if parseCert(t, pem1).SerialNumber.Cmp(parseCert(t, pem2).SerialNumber) == 0 {
		t.Error("deux certificats partagent le même numéro de série")
	}
}

// TestCertificatValideDesMaintenant : NotBefore doit être dans le passé.
//
// Les horloges d'un serveur et de son client ne sont jamais exactement
// d'accord, et un certificat « pas encore valide » échoue exactement comme un
// certificat expiré.
func TestCertificatValideDesMaintenant(t *testing.T) {
	avecHoteFactice(t, "core-01", nil)

	certPEM, _, err := GenerateLDAPSCertPEM(BuildSANSet(nil, nil))
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	cert := parseCert(t, certPEM)

	if !cert.NotBefore.Before(cert.NotAfter) {
		t.Error("période de validité vide")
	}
	if cert.NotBefore.After(cert.NotAfter) {
		t.Error("NotBefore après NotAfter")
	}
}

// TestAuditSignaleLAbsenceDeSAN : l'audit doit désigner le vrai coupable.
//
// C'est le seul endroit du système qui peut le faire : l'échec de poignée de
// main se produit chez le client, et le serveur n'en voit qu'une connexion
// fermée.
func TestAuditSignaleLAbsenceDeSAN(t *testing.T) {
	avecHoteFactice(t, "core-01", nil)

	// Le certificat d'avant le correctif, reproduit tel quel.
	ancien := certSansSAN(t)

	issues := AuditServedCertificate(ancien, BuildSANSet(nil, nil))
	if len(issues) == 0 {
		t.Fatal("aucun défaut signalé sur un certificat sans SAN")
	}

	var grave bool
	var texte string
	for _, i := range issues {
		texte += i.Message + " "
		if i.Grave {
			grave = true
		}
	}
	if !grave {
		t.Error("l'absence de SAN doit être signalée comme grave, pas comme un avertissement")
	}
	// Le message doit donner la marche à suivre : un diagnostic exact qui ne dit
	// pas quoi faire coûte la même recherche que pas de diagnostic du tout.
	if !strings.Contains(texte, "regenerate") {
		t.Errorf("le message ne dit pas comment corriger : %q", texte)
	}

	// Et il doit nommer LE défaut, pas un défaut voisin. « aucun nom DNS » et
	// « aucun SAN du tout » n'appellent pas le même geste : le premier se
	// corrige en ajoutant un nom, le second veut dire que le certificat est
	// celui d'avant le correctif et qu'il faut le remplacer entièrement.
	if !strings.Contains(texte, "AUCUN nom alternatif") {
		t.Errorf("l'absence totale de SAN doit être nommée comme telle : %q", texte)
	}
	// Le message doit aussi dire POURQUOI, sinon l'administrateur cherche du
	// côté du réseau — c'est là que part le diagnostic par défaut sur un
	// « SSLHandshakeFailed ».
	if !strings.Contains(texte, "JDK 9") {
		t.Errorf("le message n'explique pas la cause côté client : %q", texte)
	}
}

// TestAuditAccepteUnCertificatCorrect : pas de faux positif.
//
// Un audit qui crie à chaque démarrage sur un certificat sain apprend à ignorer
// le journal — ce qui coûte le diagnostic le jour où il est juste.
func TestAuditAccepteUnCertificatCorrect(t *testing.T) {
	avecHoteFactice(t, "core-01", []net.Addr{ipnet("10.0.0.5/24")})
	sans := BuildSANSet([]string{"vaultaire-ad"}, nil)

	certPEM, _, err := GenerateLDAPSCertPEM(sans)
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}

	if issues := AuditServedCertificate(certPEM, sans); len(issues) != 0 {
		t.Errorf("faux positif sur un certificat correct : %+v", issues)
	}
}

// TestAuditSignaleUnNomManquant : couverture partielle.
func TestAuditSignaleUnNomManquant(t *testing.T) {
	avecHoteFactice(t, "core-01", nil)

	certPEM, _, err := GenerateLDAPSCertPEM(BuildSANSet([]string{"vaultaire-ad"}, nil))
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}

	// On attend désormais un nom que le certificat ne porte pas.
	attendus := BuildSANSet([]string{"vaultaire-ad", "nouveau-nom.exemple.fr"}, nil)

	var trouve bool
	for _, i := range AuditServedCertificate(certPEM, attendus) {
		if strings.Contains(i.Message, "nouveau-nom.exemple.fr") {
			trouve = true
		}
	}
	if !trouve {
		t.Error("un nom attendu absent du certificat n'est pas signalé")
	}
}

// TestAuditNePaniquePasSurUneEntreeIllisible : le contenu vient de la base, qui
// a pu être éditée à la main. Une panique au démarrage empêcherait le serveur de
// démarrer pour un problème de diagnostic.
func TestAuditNePaniquePasSurUneEntreeIllisible(t *testing.T) {
	for _, entree := range []string{"", "pas du PEM", "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"} {
		if issues := AuditServedCertificate(entree, SANSet{}); len(issues) == 0 {
			t.Errorf("entrée illisible %q non signalée", entree)
		}
		if s := CertSummary(entree); s == "" {
			t.Errorf("CertSummary vide pour %q", entree)
		}
	}
}

func parseCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	bloc, _ := pem.Decode([]byte(certPEM))
	if bloc == nil {
		t.Fatal("PEM invalide")
	}
	cert, err := x509.ParseCertificate(bloc.Bytes)
	if err != nil {
		t.Fatalf("certificat illisible : %v", err)
	}
	return cert
}

// certSansSAN reproduit EXACTEMENT le certificat d'avant le correctif.
//
// Reproduit et non conservé en dur : un PEM figé expirerait et le test se
// mettrait à échouer pour la mauvaise raison, en signalant l'expiration au lieu
// de l'absence de SAN.
func certSansSAN(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("clé : %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"YNOV Labs"},
			CommonName:   "localhost", // ignoré par Java depuis JDK 9
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Aucun DNSNames, aucune IPAddresses : c'est tout le défaut.
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("certificat : %v", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem : %v", err)
	}
	return buf.String()
}
