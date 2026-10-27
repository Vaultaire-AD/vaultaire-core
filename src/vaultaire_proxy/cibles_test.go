package main

import (
	"strings"
	"testing"

	"duckynetworkclient/V1/config"
	"duckynetworkclient/V1/duckynetwork/decouverte"
)

// avecPort : les cores appris par leur adresse Ducky, joints sur un autre port.
func TestAvecPortRemplaceEtDedoublonne(t *testing.T) {
	got := avecPort([]string{"10.0.0.1:6666", "[2001:db8::1]:6666", "10.0.0.1:7666", "pas-une-adresse"}, 636)
	if strings.Join(got, ",") != "10.0.0.1:636,[2001:db8::1]:636" {
		t.Fatalf("cibles = %v : le port LDAPS doit remplacer le port Ducky, une même machine une seule fois", got)
	}
}

// TO-DO 225 : le core de la session du proxy passe avant les adresses exposées
// apprises, sans doublon ; un proxy appris n'est jamais une cible.
func TestLeCoreDeLaSessionPasseDAbord(t *testing.T) {
	appris := []decouverte.Noeud{
		{Hostname: "c1", IP: "192.168.30.3", Port: 6666, Role: "core"},
		{Hostname: "p1", IP: "192.168.30.3", Port: 6667, Role: "proxy"},
		{Hostname: "c2", IP: "10.0.0.2", Port: 6666, Role: "core"},
	}
	serveurs := []config.ServerConfig{{IP: "vaultaire-ad", Port: 6666}}
	got := ordonnerCibles("vaultaire-ad:6666", appris, serveurs)
	if strings.Join(got, ",") != "vaultaire-ad:6666,192.168.30.3:6666,10.0.0.2:6666" {
		t.Fatalf("cibles = %v", got)
	}
	if ldaps := avecPort(got, 636); ldaps[0] != "vaultaire-ad:636" {
		t.Fatalf("relais LDAPS : %v, le chemin de la session doit venir en premier", ldaps)
	}
	if got := ordonnerCibles("", appris, nil); strings.Join(got, ",") != "192.168.30.3:6666,10.0.0.2:6666" {
		t.Fatalf("sans session : %v, l'ordre servi doit rester", got)
	}
}
