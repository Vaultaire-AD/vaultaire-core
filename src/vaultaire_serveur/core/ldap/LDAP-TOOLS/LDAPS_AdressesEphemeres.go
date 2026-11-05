package ldaptools

import (
	"net"
	"os"
	"strings"
)

// L'adresse d'un pod n'est pas un nom à couvrir — TO-DO 259.
//
// Dans Kubernetes, l'adresse IP d'un pod change à chaque recréation. Le
// certificat LDAPS, lui, est conservé en base : il porte l'adresse du PREMIER
// pod. Le contrôle de démarrage signalait donc, à chaque redémarrage, « le
// certificat ne couvre pas 10.42.0.11 » — un avertissement vrai et inutile :
// aucun client ne joint un pod par son adresse, tous passent par le Service
// (dont la chart déclare les noms).
//
// En Kubernetes, l'audit ne réclame donc que les adresses DÉCLARÉES dans la
// configuration et la boucle locale ; les noms (dont celui du pod, stable dans
// un StatefulSet) restent réclamés. La génération, elle, ne change pas : une
// adresse de trop dans un certificat n'ouvre rien.

// EnKubernetes dit si le core tourne dans un pod. Kubernetes pose toujours
// KUBERNETES_SERVICE_HOST, y compris avec enableServiceLinks: false.
func EnKubernetes() bool {
	return strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")) != ""
}

// AttendusPourAudit rend l'ensemble que l'audit doit réclamer.
func AttendusPourAudit(set SANSet, ipsConfigurees []string) SANSet {
	if !EnKubernetes() {
		return set
	}
	return sansAdressesDetectees(set, ipsConfigurees)
}

func sansAdressesDetectees(set SANSet, ipsConfigurees []string) SANSet {
	gardees := map[string]bool{"127.0.0.1": true, "::1": true}
	for _, v := range ipsConfigurees {
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			gardees[ip.String()] = true
		}
	}
	out := SANSet{DNSNames: set.DNSNames}
	for _, ip := range set.IPs {
		if gardees[ip.String()] {
			out.IPs = append(out.IPs, ip)
		}
	}
	return out
}
