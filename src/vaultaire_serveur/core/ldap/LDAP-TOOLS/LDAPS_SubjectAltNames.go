package ldaptools

import (
	"net"
	"sort"
	"strings"
)

// Noms alternatifs du certificat LDAPS — RFC 5280 §4.2.1.6.
//
// # Pourquoi ce fichier existe
//
// Le certificat auto-signé ne portait qu'un `CommonName: "localhost"` et un seul
// SAN, `127.0.0.1`. Or depuis JDK 9, la vérification du nom d'hôte côté Java
// IGNORE complètement le CommonName : elle exige un SAN correspondant. Tout
// client Java — Keycloak, un connecteur applicatif, un annuaire secondaire — qui
// se connecte à `ldaps://vaultaire-ad:636` échouait donc à la poignée de main,
// avec un message qui ne dit pas que le certificat est en cause :
//
//	Error when trying to connect to LDAP: 'SSLHandshakeFailed'
//
// Le CommonName est déprécié comme identifiant d'hôte depuis RFC 2818 (2000) et
// interdit depuis RFC 6125 (2011). Les navigateurs l'ont abandonné, les JVM
// aussi. Le remplir ne coûte rien mais ne sert plus à rien.
//
// # Ce que la détection automatique attrape, et ce qu'elle rate
//
// Elle relève le nom de la machine et ses adresses. Elle ne peut PAS deviner le
// nom par lequel un client la joint quand celui-ci diffère : un enregistrement
// DNS de service, un nom de conteneur, un alias derrière un répartiteur. C'est
// exactement le cas d'un déploiement conteneurisé, où le nom d'hôte est un
// identifiant aléatoire et où les clients utilisent le nom du service.
//
// D'où la configuration : la détection est un défaut commode, pas une promesse.

// SANSet rassemble les noms et adresses que le certificat doit couvrir.
type SANSet struct {
	DNSNames []string
	IPs      []net.IP
}

// BuildSANSet fusionne les valeurs configurées et celles détectées sur l'hôte.
//
// Fusion et non remplacement : déclarer un nom de service ne doit pas faire
// perdre l'adresse locale par laquelle l'administrateur teste depuis la machine
// elle-même. Un SAN de trop n'ouvre rien — il ne fait qu'élargir la liste des
// noms sous lesquels CE serveur s'annonce.
func BuildSANSet(dnsConfigures, ipsConfigurees []string) SANSet {
	noms := map[string]bool{}
	ips := map[string]net.IP{}

	ajouterNom := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		// Un nom vide, une adresse glissée dans la liste des noms : on ne les
		// range pas parmi les DNSNames, où ils ne serviraient à rien. Une IP
		// dans un SAN DNS n'est jamais comparée par les clients.
		if n == "" {
			return
		}
		if ip := net.ParseIP(n); ip != nil {
			ips[ip.String()] = ip
			return
		}
		noms[n] = true
	}
	ajouterIP := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if ip := net.ParseIP(v); ip != nil {
			ips[ip.String()] = ip
			return
		}
		// Inversement : un nom glissé dans la liste des adresses est récupéré
		// plutôt que jeté. Se tromper de colonne dans un fichier de
		// configuration ne doit pas produire un certificat silencieusement
		// incomplet.
		noms[strings.ToLower(v)] = true
	}

	for _, n := range dnsConfigures {
		ajouterNom(n)
	}
	for _, v := range ipsConfigurees {
		ajouterIP(v)
	}

	for _, n := range nomsDetectes() {
		ajouterNom(n)
	}
	for _, ip := range adressesDetectees() {
		ips[ip.String()] = ip
	}

	// localhost et la boucle locale, toujours : c'est par là que passent les
	// tests depuis la machine elle-même, et les perdre transformerait un
	// diagnostic en seconde panne.
	ajouterNom("localhost")
	ips["127.0.0.1"] = net.ParseIP("127.0.0.1")
	ips["::1"] = net.ParseIP("::1")

	set := SANSet{}
	for n := range noms {
		set.DNSNames = append(set.DNSNames, n)
	}
	for _, ip := range ips {
		set.IPs = append(set.IPs, ip)
	}

	// Tri : un certificat régénéré à configuration identique doit être
	// comparable au précédent. L'ordre d'itération d'une map ne l'est pas.
	sort.Strings(set.DNSNames)
	sort.Slice(set.IPs, func(i, j int) bool { return set.IPs[i].String() < set.IPs[j].String() })

	return set
}

// nomsDetectes relève le nom de la machine et son nom pleinement qualifié.
func nomsDetectes() []string {
	var out []string

	hostname, err := osHostname()
	if err != nil || hostname == "" {
		return out
	}
	out = append(out, hostname)

	// Le nom court ET le nom qualifié : un client peut utiliser l'un ou
	// l'autre, et un SAN ne se compare pas par suffixe.
	if canon, err := netLookupCNAME(hostname); err == nil {
		canon = strings.TrimSuffix(canon, ".")
		if canon != "" && !strings.EqualFold(canon, hostname) {
			out = append(out, canon)
		}
	}
	if i := strings.Index(hostname, "."); i > 0 {
		out = append(out, hostname[:i])
	}

	return out
}

// adressesDetectees relève les adresses des interfaces, hors boucle locale.
//
// La boucle locale est ajoutée séparément et inconditionnellement : la relever
// ici la rendrait dépendante de l'état des interfaces.
func adressesDetectees() []net.IP {
	var out []net.IP

	adresses, err := netInterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range adresses {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ip)
	}
	return out
}
