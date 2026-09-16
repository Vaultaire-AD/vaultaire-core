package ldaptools

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

// Diagnostic du certificat LDAPS servi.
//
// # Le problème que cela résout
//
// Le certificat est persisté en base : le serveur ne le régénère que s'il n'y en
// a pas. Un parc déjà déployé continue donc de servir l'ancien certificat sans
// SAN, et corriger le générateur n'y change rien.
//
// Pire, l'échec est muet côté serveur. La poignée de main échoue chez le CLIENT,
// qui affiche un message générique ; le journal du serveur, lui, ne montre
// qu'une connexion ouverte puis fermée. Rien ne relie les deux.
//
// D'où ce contrôle au démarrage : il ne corrige rien — remplacer un certificat
// tout seul changerait l'empreinte que les clients ont épinglée — mais il DIT ce
// qui ne va pas, et il le dit du bon côté.

// CertIssue est un défaut constaté sur le certificat servi.
type CertIssue struct {
	Grave   bool
	Message string
}

// AuditServedCertificate examine le certificat PEM effectivement servi.
func AuditServedCertificate(certPEM string, attendus SANSet) []CertIssue {
	var issues []CertIssue

	bloc, _ := pem.Decode([]byte(certPEM))
	if bloc == nil {
		return []CertIssue{{true, "certificat illisible : PEM invalide"}}
	}
	cert, err := x509.ParseCertificate(bloc.Bytes)
	if err != nil {
		return []CertIssue{{true, "certificat illisible : " + err.Error()}}
	}

	// --- Absence totale de SAN : la cause du SSLHandshakeFailed côté Java ----
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		issues = append(issues, CertIssue{true,
			"le certificat ne porte AUCUN nom alternatif (SAN). Les clients Java " +
				"(Keycloak, connecteurs JNDI) ignorent le CommonName depuis JDK 9 et " +
				"refuseront la connexion avec « SSLHandshakeFailed ». " +
				"Régénérez-le : vlt certificate regenerate ldaps"})
	} else if len(cert.DNSNames) == 0 {
		issues = append(issues, CertIssue{true,
			"le certificat ne porte aucun nom DNS, seulement des adresses IP. " +
				"Une connexion par nom d'hôte échouera. " +
				"Régénérez-le : vlt certificate regenerate ldaps"})
	}

	// --- Noms attendus absents du certificat --------------------------------
	//
	// Non bloquant : un nom détecté sur l'hôte n'est pas forcément celui par
	// lequel les clients passent, et signaler cela comme une panne ferait
	// ignorer le reste du message.
	var manquants []string
	for _, n := range attendus.DNSNames {
		if !contientNom(cert.DNSNames, n) {
			manquants = append(manquants, n)
		}
	}
	for _, ip := range attendus.IPs {
		if !contientIP(cert.IPAddresses, ip) {
			manquants = append(manquants, ip.String())
		}
	}
	if len(manquants) > 0 && len(cert.DNSNames)+len(cert.IPAddresses) > 0 {
		issues = append(issues, CertIssue{false, fmt.Sprintf(
			"le certificat ne couvre pas %s — un client qui s'y connecte par un de ces noms sera refusé",
			strings.Join(manquants, ", "))})
	}

	// --- Expiration ---------------------------------------------------------
	//
	// Une expiration produit EXACTEMENT le même message côté client que
	// l'absence de SAN. Sans cette ligne, un administrateur qui vient de
	// régénérer son certificat chercherait le défaut là où il n'est plus.
	maintenant := time.Now()
	switch {
	case maintenant.After(cert.NotAfter):
		issues = append(issues, CertIssue{true, fmt.Sprintf(
			"certificat EXPIRÉ depuis le %s", cert.NotAfter.Format("2006-01-02"))})
	case maintenant.Before(cert.NotBefore):
		issues = append(issues, CertIssue{true, fmt.Sprintf(
			"certificat pas encore valide (début le %s) — vérifiez l'horloge du serveur",
			cert.NotBefore.Format("2006-01-02 15:04"))})
	case maintenant.Add(30 * 24 * time.Hour).After(cert.NotAfter):
		issues = append(issues, CertIssue{false, fmt.Sprintf(
			"certificat expirant le %s, dans moins de 30 jours",
			cert.NotAfter.Format("2006-01-02"))})
	}

	return issues
}

// CertSummary rend une description courte pour le journal de démarrage.
func CertSummary(certPEM string) string {
	bloc, _ := pem.Decode([]byte(certPEM))
	if bloc == nil {
		return "certificat illisible"
	}
	cert, err := x509.ParseCertificate(bloc.Bytes)
	if err != nil {
		return "certificat illisible"
	}

	noms := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		noms = append(noms, ip.String())
	}
	if len(noms) == 0 {
		noms = []string{"aucun SAN"}
	}
	return fmt.Sprintf("sujet %q, valide jusqu'au %s, couvre %s",
		cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02"), strings.Join(noms, ", "))
}

// contientNom compare des noms d'hôte sans tenir compte de la casse : un nom DNS
// n'y est pas sensible, et comparer octet à octet signalerait des manques faux.
func contientNom(liste []string, nom string) bool {
	for _, v := range liste {
		if strings.EqualFold(v, nom) {
			return true
		}
	}
	return false
}

// contientIP compare par valeur et non par représentation : « ::1 » et
// « 0:0:0:0:0:0:0:1 » sont la même adresse écrite de deux façons.
func contientIP(liste []net.IP, ip net.IP) bool {
	for _, v := range liste {
		if v.Equal(ip) {
			return true
		}
	}
	return false
}
