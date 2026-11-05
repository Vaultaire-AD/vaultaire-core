package ldaptools

import (
	"net"
	"strings"
)

// AttendusDeclares rend les noms qu'un certificat IMPORTÉ doit couvrir — TO-DO 262.
//
// Seulement ceux de la configuration : sans la détection sur l'hôte (nom du
// pod, adresses), sans localhost. Un certificat émis par cert-manager ou par
// une PKI couvre les noms par lesquels les clients joignent le service, que
// l'exploitant a choisis ; lui réclamer le nom de la machine produirait un
// avertissement à chaque démarrage, vrai et inutile.
func AttendusDeclares(dnsConfigures, ipsConfigurees []string) SANSet {
	set := SANSet{}
	vus := map[string]bool{}
	ajouter := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || vus[v] {
			return
		}
		vus[v] = true
		if ip := net.ParseIP(v); ip != nil {
			set.IPs = append(set.IPs, ip)
			return
		}
		set.DNSNames = append(set.DNSNames, v)
	}
	for _, v := range dnsConfigures {
		ajouter(v)
	}
	for _, v := range ipsConfigurees {
		ajouter(v)
	}
	return set
}
