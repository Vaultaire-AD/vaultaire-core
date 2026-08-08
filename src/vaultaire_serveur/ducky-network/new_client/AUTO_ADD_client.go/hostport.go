package autoaddclientgo

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// PortSSHParDefaut est le port employé quand la cible n'en précise aucun.
//
// La valeur reste 22 : c'est le port de service normalisé, et l'immense
// majorité des machines l'écoute. Ce qui change est qu'elle n'est plus la SEULE
// possible.
const PortSSHParDefaut = 22

// SeparerHoteEtPort accepte les formes que l'on écrit naturellement pour
// désigner une machine, et rend l'hôte et le port séparément.
//
//	192.168.30.8            → 192.168.30.8, 22
//	192.168.30.8:2222       → 192.168.30.8, 2222
//	serveur.exemple.fr      → serveur.exemple.fr, 22
//	serveur.exemple.fr:2222 → serveur.exemple.fr, 2222
//	[2001:db8::1]:2222      → 2001:db8::1, 2222
//	2001:db8::1             → 2001:db8::1, 22
//
// # Le cas qui rend cette fonction nécessaire
//
// Une adresse IPv6 nue contient des deux-points. Découper naïvement sur le
// dernier « : » transformerait « 2001:db8::1 » en hôte « 2001:db8: » et port
// « 1 » — une cible inexistante, et un message d'erreur qui n'aiderait
// personne.
//
// La convention est donc celle de la RFC 3986 §3.2.2, la même que partout
// ailleurs : une adresse IPv6 suivie d'un port s'écrit entre crochets. Sans
// crochets, tout ce qui contient plus d'un « : » est une adresse, pas un
// couple hôte-port.
//
// C'est exactement ce que net.SplitHostPort implémente, d'où son emploi ici
// plutôt qu'un découpage maison.
func SeparerHoteEtPort(cible string) (string, int, error) {
	cible = strings.TrimSpace(cible)
	if cible == "" {
		return "", 0, fmt.Errorf("hôte vide")
	}

	hote, portTexte, err := net.SplitHostPort(cible)
	if err != nil {
		// Pas de port : soit un nom ou une IPv4 nue, soit une IPv6 nue.
		// SplitHostPort rend « missing port » dans le premier cas et « too many
		// colons » dans le second. Les deux sont des cibles valides sans port.
		//
		// On vérifie tout de même l'absence de crochet orphelin : « [::1] » sans
		// port, ou « [::1:22 » mal fermé, sont des saisies fautives qu'il vaut
		// mieux signaler que traiter comme un nom d'hôte.
		if strings.ContainsAny(cible, "[]") {
			return "", 0, fmt.Errorf(
				"cible %q mal formée : une adresse IPv6 avec port s'écrit [adresse]:port", cible)
		}
		return cible, PortSSHParDefaut, nil
	}

	if hote == "" {
		return "", 0, fmt.Errorf("cible %q : port indiqué sans hôte", cible)
	}

	port, err := strconv.Atoi(portTexte)
	if err != nil {
		return "", 0, fmt.Errorf("port %q dans %q : ce n'est pas un nombre", portTexte, cible)
	}
	// Borne haute 65535 : au-delà, le numéro ne tient pas dans un en-tête TCP.
	// Borne basse 1 : le port 0 demande au système d'en choisir un, ce qui n'a
	// aucun sens pour une destination.
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port %d hors de la plage 1-65535", port)
	}

	return hote, port, nil
}
