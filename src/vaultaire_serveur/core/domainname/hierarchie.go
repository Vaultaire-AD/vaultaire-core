// Package domainname porte la FORME des noms de domaine de l'annuaire :
// normalisation, validation, domaine principal, ancêtres.
//
// Paquet feuille, sans accès à la base : les paquets de base (db_groups,
// db_domains) et le réseau Ducky l'importent sans créer de cycle.
package domainname

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Hiérarchie des domaines : forme, domaine principal, ancêtres.
//
// # Le domaine principal
//
// Le domaine principal (on dit aussi « global » ou « racine ») est formé des
// DEUX derniers labels : infra.cloud.test.fr → test.fr. C'est le domaine sous
// lequel un compte s'identifie (`alice@test.fr`) et le plus haut qu'on crée
// automatiquement — un domaine d'un seul label (`fr`, `lan`) n'est jamais créé.
//
// Les suffixes publics à deux labels (`co.uk`) ne sont pas reconnus : un parc
// sous `acme.co.uk` aurait `co.uk` pour domaine principal. Ce n'est pas un cas
// rencontré aujourd'hui ; le jour où il le sera, c'est ici qu'il se traite.

// labelRe est un label DNS : lettres minuscules, chiffres, tiret intérieur.
var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormaliserDomaine ramène un domaine à sa forme canonique : minuscules, sans
// espaces ni point final. `Acme.LAN.` et `acme.lan` désignent le même domaine
// et ne doivent pas produire deux branches de l'arbre, ni deux comptes locaux.
func NormaliserDomaine(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// ValiderDomaine refuse ce qui ne peut pas être un domaine de l'annuaire.
//
// Au moins deux labels : un groupe placé directement sous `lan` n'aurait pas
// de domaine principal, donc aucun identifiant de connexion possible.
func ValiderDomaine(d string) error {
	n := NormaliserDomaine(d)
	if n == "" {
		return fmt.Errorf("domaine vide")
	}
	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domaine %q invalide : il faut au moins deux labels (ex. acme.lan)", d)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return fmt.Errorf("domaine %q invalide : label %q (lettres, chiffres et tirets seulement)", d, l)
		}
	}
	return nil
}

// DomainePrincipal rend le domaine principal (deux derniers labels), normalisé.
func DomainePrincipal(d string) (string, error) {
	labels := strings.Split(NormaliserDomaine(d), ".")
	if len(labels) < 2 || labels[len(labels)-2] == "" || labels[len(labels)-1] == "" {
		return "", errors.New("domaine invalide")
	}
	n := len(labels)
	return labels[n-2] + "." + labels[n-1], nil
}

// Ancetres rend les domaines parents de d, du domaine principal au parent
// direct, d EXCLU : infra.cloud.acme.lan → [acme.lan, cloud.acme.lan].
//
// Un domaine principal n'a pas d'ancêtre : acme.lan → [].
func Ancetres(d string) []string {
	n := NormaliserDomaine(d)
	labels := strings.Split(n, ".")
	if len(labels) <= 2 {
		return nil
	}
	var out []string
	// Du plus court (le principal) au plus long (le parent direct) : l'ordre de
	// création, pour qu'un parent existe toujours avant son enfant.
	for i := len(labels) - 2; i >= 1; i-- {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// DomainesPrincipaux rend l'ensemble des domaines principaux d'une liste de
// domaines, sans doublon, dans l'ordre de première apparition.
func DomainesPrincipaux(domaines []string) []string {
	vus := map[string]bool{}
	var out []string
	for _, d := range domaines {
		p, err := DomainePrincipal(d)
		if err != nil || vus[p] {
			continue
		}
		vus[p] = true
		out = append(out, p)
	}
	return out
}

// SousDomaineDe dit si d est égal à parent ou situé sous lui.
func SousDomaineDe(d, parent string) bool {
	d, parent = NormaliserDomaine(d), NormaliserDomaine(parent)
	return d == parent || strings.HasSuffix(d, "."+parent)
}
