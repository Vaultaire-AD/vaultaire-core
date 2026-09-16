package ratelimit

import (
	"net"
	"net/http"
	"strings"
)

// ProxiesDeConfiance liste les relais autorisés à déclarer l'adresse réelle du
// client, en adresses simples ou en préfixes CIDR.
//
// VIDE PAR DÉFAUT, et c'est le point important.
//
// Sans relais déclaré, `X-Forwarded-For` est ignoré. Faire l'inverse — croire
// l'en-tête parce qu'il est présent — serait PIRE que de ne rien limiter : cet
// en-tête est écrit par le client, donc un attaquant en met une valeur
// différente à chaque tentative, obtient un compteur neuf à chaque coup, et
// contourne entièrement la limitation par source. Il pourrait même y placer
// l'adresse d'un collègue pour la faire pénaliser à sa place.
//
// L'en-tête n'est cru que si le pair TCP — celui-là ne se falsifie pas sans
// tenir le chemin réseau — figure dans cette liste.
//
// À renseigner quand le portail est publié derrière un reverse proxy ou un
// répartiteur de charge : sans cela toutes les requêtes portent l'adresse du
// relais, la limitation par source devient une limitation globale, et le premier
// balayage venu freine tout le monde.
var ProxiesDeConfiance []string

// SourceHTTP rend l'identifiant de source d'une requête web : une adresse IP,
// sans le port.
//
// Sans le port, parce qu'il change à chaque connexion : chaque tentative aurait
// sa propre clé et le compteur par source ne dépasserait jamais un.
func SourceHTTP(r *http.Request) string {
	if r == nil {
		return ""
	}
	pair := hote(r.RemoteAddr)
	if !estDeConfiance(pair) {
		return pair
	}

	// La chaîne se lit de gauche à droite : le client d'origine d'abord, puis
	// chaque relais traversé. On prend la dernière valeur NON produite par un
	// relais de confiance — les précédentes ont pu être écrites par le client.
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return pair
	}
	champs := strings.Split(xff, ",")
	for i := len(champs) - 1; i >= 0; i-- {
		ip := hote(strings.TrimSpace(champs[i]))
		if ip == "" {
			continue
		}
		if estDeConfiance(ip) {
			continue
		}
		return ip
	}
	return pair
}

// hote retire le port s'il y en a un, et normalise l'adresse.
func hote(adresse string) string {
	adresse = strings.TrimSpace(adresse)
	if adresse == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(adresse); err == nil {
		adresse = h
	}
	// Forme « [::1] » sans port, que SplitHostPort refuse.
	adresse = strings.TrimPrefix(adresse, "[")
	adresse = strings.TrimSuffix(adresse, "]")
	if ip := net.ParseIP(adresse); ip != nil {
		// Normalisation : « ::ffff:10.0.0.1 » et « 10.0.0.1 » désignent la même
		// machine. Sans cela, un même attaquant compterait deux fois moins.
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return adresse
}

func estDeConfiance(ip string) bool {
	if ip == "" || len(ProxiesDeConfiance) == 0 {
		return false
	}
	adresse := net.ParseIP(ip)
	if adresse == nil {
		return false
	}
	for _, entree := range ProxiesDeConfiance {
		entree = strings.TrimSpace(entree)
		if entree == "" {
			continue
		}
		if strings.Contains(entree, "/") {
			if _, reseau, err := net.ParseCIDR(entree); err == nil && reseau.Contains(adresse) {
				return true
			}
			continue
		}
		if attendue := net.ParseIP(entree); attendue != nil && attendue.Equal(adresse) {
			return true
		}
	}
	return false
}

// SourceConn rend l'identifiant de source d'une connexion : l'adresse du pair,
// sans le port. Pour le bind LDAP.
func SourceConn(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return hote(conn.RemoteAddr().String())
}
