package hosthandler

import (
	"strings"
	"testing"

	"vaultaire/core/clienttype"
)

// La réponse 04_16 : la liste des services vers qui un proxy relaie en HTTPS.
//
// # Ce que ces tests gardent
//
//   - l'URL publique d'un Nexus devient une adresse qu'on peut COMPOSER : un
//     port manquant ou un schéma mal lu, et le relais ouvre une connexion vers
//     un port où rien n'écoute ;
//   - l'ordre est fixe, priorité d'abord : un docker pull ne doit pas se
//     promener entre deux dépôts ;
//   - le proxy ne peut pas se faire servir des proxies.

func TestLAdresseSeDeduitDuPointDAcces(t *testing.T) {
	cas := map[string]string{
		"https://nexus.acme.lan:8843":     "nexus.acme.lan:8843",
		"https://nexus.acme.lan":          "nexus.acme.lan:443",
		"https://nexus.acme.lan/depots/":  "nexus.acme.lan:443",
		"http://10.0.0.8":                 "10.0.0.8:80",
		"https://[2001:db8::8]:8843/":     "[2001:db8::8]:8843",
		"nexus.acme.lan:8843":             "nexus.acme.lan:8843",
		"  https://NEXUS.acme.lan:8843  ": "NEXUS.acme.lan:8843",
	}
	for point, attendue := range cas {
		got, err := AdresseDeService(point)
		if err != nil || got != attendue {
			t.Errorf("AdresseDeService(%q) = %q, %v ; attendu %q", point, got, err, attendue)
		}
	}
}

func TestUnPointDAccesInutilisableEstRefuse(t *testing.T) {
	for _, point := range []string{"", "nexus.acme.lan", "ftp://nexus.acme.lan", "https://:8843", "https://"} {
		if got, err := AdresseDeService(point); err == nil {
			t.Errorf("AdresseDeService(%q) = %q accepté : le relais composerait une adresse inventée", point, got)
		}
	}
}

func TestLOrdreDesServicesEstFixe(t *testing.T) {
	s := []ServiceJoignable{
		{Hostname: "nexus-c", Priorite: 0},
		{Hostname: "nexus-b", Priorite: 2},
		{Hostname: "nexus-a", Priorite: 0},
		{Hostname: "nexus-d", Priorite: 1},
	}
	TrierServices(s)
	var noms []string
	for _, x := range s {
		noms = append(noms, x.Hostname)
	}
	if got := strings.Join(noms, ","); got != "nexus-d,nexus-b,nexus-a,nexus-c" {
		t.Fatalf("ordre = %s : priorités explicites d'abord, puis sans priorité, puis le nom", got)
	}
}

func TestSeulsLesServicesSontRelayables(t *testing.T) {
	if !typeDeServiceRelayable(clienttype.Nexus) {
		t.Error("Nexus n'est pas relayable : le relais HTTPS n'aurait aucune cible")
	}
	for _, typ := range []string{clienttype.Proxy, clienttype.Client, "inconnu", ""} {
		if typeDeServiceRelayable(typ) {
			t.Errorf("%q relayable : un proxy pourrait relayer vers un proxy, ou vers un poste", typ)
		}
	}
}
