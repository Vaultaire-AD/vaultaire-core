package security

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"time"
	"vaultaire/core/storage"
)

// Identité des certificats auto-signés servis par le serveur web et l'API REST.
//
// # Ce qui manquait
//
// Les certificats produits ici ne portaient NI CommonName NI SubjectAltName :
//
//	Subject: pkix.Name{Organization: []string{"SSO Vaultaire"}}
//
// Un certificat sans nom ne peut identifier personne. Tout client TLS qui
// vérifie l'identité du serveur — c'est-à-dire tout client correctement
// configuré — le rejette, avec un message qui varie selon l'outil :
//
//	Go     : x509: certificate is not valid for any names
//	curl   : SSL: no alternative certificate subject name matches
//	Chrome : ERR_CERT_COMMON_NAME_INVALID
//
// Le défaut passait inaperçu parce que les clients internes désactivaient la
// vérification. C'est un cercle : le certificat est invérifiable, donc on cesse
// de vérifier, donc plus personne ne remarque qu'il est invérifiable. Et une
// fois la vérification désactivée, elle l'est pour TOUS les certificats — y
// compris celui qu'un tiers présenterait à la place du nôtre.
//
// # Pourquoi les deux, CN et SAN
//
// Le SAN est ce qui compte : la RFC 6125 §6.4.4 le rend prioritaire, et depuis
// le JDK 9 comme depuis Chrome 58, le CommonName est purement et simplement
// ignoré pour la validation.
//
// Le CommonName est renseigné quand même, parce qu'il reste ce que les outils
// AFFICHENT. « openssl x509 -subject », l'inspecteur de certificat d'un
// navigateur, une liste de certificats en base : tous montrent le sujet. Un
// sujet vide ne dit pas à l'administrateur de quelle machine il s'agit.
//
// Il ne sert donc pas à valider — il sert à lire.

// hooks d'injection pour les tests. La détection interroge la machine ; sans
// eux, un test vérifierait la machine de compilation plutôt que le code.
var (
	osHostname        = os.Hostname
	netInterfaceAddrs = net.InterfaceAddrs
)

// identiteCertificat rassemble les noms sous lesquels le serveur peut être
// joint.
type identiteCertificat struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
}

// construireIdentite détermine les noms à inscrire dans le certificat.
//
// Trois sources, cumulées :
//
//  1. ce que l'administrateur a déclaré en configuration ;
//  2. le nom de la machine ;
//  3. les adresses de ses interfaces.
//
// Cumulées et non exclusives : déclarer un nom de service public ne doit pas
// faire perdre l'adresse locale par laquelle l'administrateur teste depuis la
// machine elle-même. Une omission ici se paie par une erreur TLS que rien ne
// rattache à ce fichier.
func construireIdentite() identiteCertificat {
	return construireIdentiteAvec(nil, nil)
}

// construireIdentiteAvec ajoute des noms et des adresses fournis à la volée.
//
// # Pourquoi ce paramètre existe
//
// Les certificats du portail et de l'API sont produits UNE FOIS, au premier
// démarrage, puis conservés en base. Déclarer `web_tls_dns_names` après coup
// n'avait donc aucun effet : le certificat déjà stocké n'était jamais
// reconstruit, et l'administrateur voyait sa configuration ignorée sans qu'un
// message le dise.
//
// `vlt certificate regenerate web` reconstruit le certificat, et ses options
// `--dns` / `--ip` passent par ici — pour couvrir un nom sans avoir à modifier
// la configuration puis redémarrer, quand on cherche encore lequel il faut.
//
// Les valeurs fournies s'AJOUTENT à la configuration et à la détection
// automatique : régénérer avec `--dns sso.exemple.fr` ne doit pas faire perdre
// l'adresse locale par laquelle on teste.
func construireIdentiteAvec(dnsSupplementaires, ipsSupplementaires []string) identiteCertificat {
	noms := map[string]bool{}
	ips := map[string]net.IP{}

	ajouterNom := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		n = strings.TrimSuffix(n, ".")
		if n == "" {
			return
		}
		// Une adresse glissée dans la liste des noms : on la range du bon côté.
		// Un SAN de type DNS contenant une IP n'est comparé par aucun client —
		// il serait présent sans jamais servir.
		if ip := net.ParseIP(n); ip != nil {
			ips[ip.String()] = ip
			return
		}
		noms[n] = true
	}
	ajouterIP := func(brut string) {
		brut = strings.TrimSpace(brut)
		if brut == "" {
			return
		}
		if ip := net.ParseIP(brut); ip != nil {
			ips[ip.String()] = ip
			return
		}
		// Inversement : un nom glissé parmi les adresses.
		ajouterNom(brut)
	}

	// 1. Configuration.
	for _, n := range storage.Web_TLS_DNSNames {
		ajouterNom(n)
	}
	for _, a := range storage.Web_TLS_IPs {
		ajouterIP(a)
	}

	// 1 bis. Ce que la commande de régénération a passé sur la ligne.
	for _, n := range dnsSupplementaires {
		ajouterNom(n)
	}
	for _, a := range ipsSupplementaires {
		ajouterIP(a)
	}

	// 2. Nom de la machine. Le nom court ET le nom long : selon la manière dont
	// l'administrateur atteint le serveur, l'un ou l'autre est présenté dans
	// l'URL, et le client compare exactement ce qu'il a saisi.
	hote, err := osHostname()
	if err == nil && hote != "" {
		ajouterNom(hote)
		if i := strings.Index(hote, "."); i > 0 {
			ajouterNom(hote[:i])
		}
	}

	// 3. Adresses des interfaces, hors bouclage — celui-ci est ajouté plus bas
	// de toute façon.
	if adresses, err := netInterfaceAddrs(); err == nil {
		for _, a := range adresses {
			reseau, ok := a.(*net.IPNet)
			if !ok || reseau.IP == nil || reseau.IP.IsLoopback() {
				continue
			}
			// Les adresses de lien-local IPv6 (fe80::/10) ne sont pas
			// routables et ne servent à joindre le service depuis nulle part.
			// Les inscrire allongerait le certificat sans rien y ajouter.
			if reseau.IP.IsLinkLocalUnicast() {
				continue
			}
			ips[reseau.IP.String()] = reseau.IP
		}
	}

	// Toujours : l'accès depuis la machine elle-même. C'est le premier essai de
	// tout administrateur qui vérifie que le service répond, et son échec
	// donnerait l'impression que le certificat est cassé alors qu'il ne
	// manquerait que ce cas.
	ajouterNom("localhost")
	ips["127.0.0.1"] = net.ParseIP("127.0.0.1")
	ips["::1"] = net.ParseIP("::1")

	id := identiteCertificat{}
	for n := range noms {
		id.DNSNames = append(id.DNSNames, n)
	}
	sort.Strings(id.DNSNames)

	clesIP := make([]string, 0, len(ips))
	for k := range ips {
		clesIP = append(clesIP, k)
	}
	sort.Strings(clesIP)
	for _, k := range clesIP {
		id.IPs = append(id.IPs, ips[k])
	}

	id.CommonName = choisirCommonName(id.DNSNames)
	return id
}

// choisirCommonName retient le nom le plus informatif pour l'affichage.
//
// Priorité au nom pleinement qualifié — celui qui contient un point. Il désigne
// la machine sans ambiguïté, là où un nom court se répète d'un domaine à
// l'autre : trois serveurs nommés « vaultaire-ad » dans trois domaines
// différents s'afficheraient identiquement dans une liste de certificats.
//
// « localhost » est écarté pour la même raison, en pire : il vaudrait pour
// toutes les machines à la fois.
//
// Le tri alphabétique ne convenait pas comme critère : « vaultaire-ad » précède
// « vaultaire-ad.exemple.fr », donc prendre le premier revenait à préférer
// systématiquement la forme la moins précise, sans que ce choix ait été fait.
func choisirCommonName(noms []string) string {
	repli := ""
	for _, n := range noms {
		if n == "localhost" {
			continue
		}
		if strings.Contains(n, ".") {
			return n
		}
		if repli == "" {
			repli = n
		}
	}
	if repli != "" {
		return repli
	}
	// Aucun nom exploitable : plutôt qu'un sujet vide, une valeur qui dit au
	// moins de quel logiciel provient le certificat.
	return "vaultaire"
}

// sujetCertificat construit le champ Subject.
func (id identiteCertificat) sujet() pkix.Name {
	return pkix.Name{
		Organization: []string{"SSO Vaultaire"},
		CommonName:   id.CommonName,
	}
}

// numeroDeSerie tire un numéro de série sur 128 bits.
//
// L'ancienne version employait big.NewInt(1<<62), soit 62 bits. La RFC 5280
// §4.1.2.2 exige que le couple (émetteur, numéro de série) soit unique, et
// recommande au moins 64 bits d'entropie — précisément parce que plusieurs
// magasins de confiance indexent les certificats par ce couple : deux
// certificats qui le partagent se remplacent l'un l'autre au lieu de coexister.
//
// Avec des certificats auto-signés, l'émetteur est identique d'une machine à
// l'autre — même Organization, et le CommonName peut se répéter sur des
// machines homonymes. Le numéro de série devient alors le seul discriminant.
func numeroDeSerie() (*big.Int, error) {
	limite := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limite)
}

// margeAntidatage recule NotBefore de quelques minutes.
//
// Les horloges de deux machines diffèrent presque toujours de quelques
// secondes. Sans marge, un client dont l'horloge retarde légèrement rejette un
// certificat fraîchement émis comme « pas encore valide » — une erreur qui
// disparaît d'elle-même quelques minutes plus tard, ce qui la rend
// particulièrement pénible à diagnostiquer.
const margeAntidatage = 5 * time.Minute

func periodeValidite() (time.Time, time.Time) {
	maintenant := time.Now()
	return maintenant.Add(-margeAntidatage), maintenant.Add(365 * 24 * time.Hour)
}
