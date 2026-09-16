package autoaddclientgo

import "testing"

func TestSeparerHoteEtPort(t *testing.T) {
	cas := []struct {
		nom         string
		cible       string
		hote        string
		port        int
		doitEchouer bool
	}{
		// Sans port : le comportement d'avant, qui doit rester intact.
		{"IPv4 nue", "192.168.30.8", "192.168.30.8", 22, false},
		{"nom d'hôte nu", "serveur.exemple.fr", "serveur.exemple.fr", 22, false},
		{"nom court", "rocky9", "rocky9", 22, false},

		// Avec port : ce que le correctif apporte.
		{"IPv4 et port", "192.168.30.8:2222", "192.168.30.8", 2222, false},
		{"nom et port", "serveur.exemple.fr:2222", "serveur.exemple.fr", 2222, false},
		{"port 22 explicite", "192.168.30.8:22", "192.168.30.8", 22, false},
		{"port maximal", "10.0.0.1:65535", "10.0.0.1", 65535, false},

		// IPv6 : le cas qui justifie net.SplitHostPort plutôt qu'un découpage
		// sur le dernier « : ».
		{"IPv6 nue", "2001:db8::1", "2001:db8::1", 22, false},
		{"IPv6 bouclage", "::1", "::1", 22, false},
		{"IPv6 entre crochets et port", "[2001:db8::1]:2222", "2001:db8::1", 2222, false},
		{"IPv6 bouclage et port", "[::1]:2222", "::1", 2222, false},

		// Saisies fautives : mieux vaut refuser que deviner.
		{"vide", "", "", 0, true},
		{"espaces seuls", "   ", "", 0, true},
		{"port non numérique", "192.168.30.8:ssh", "", 0, true},
		{"port zéro", "192.168.30.8:0", "", 0, true},
		{"port hors plage", "192.168.30.8:70000", "", 0, true},
		{"port négatif", "192.168.30.8:-1", "", 0, true},
		{"port sans hôte", ":2222", "", 0, true},
		{"crochet non fermé", "[2001:db8::1:2222", "", 0, true},
		{"IPv6 entre crochets sans port", "[2001:db8::1]", "", 0, true},

		// Les espaces autour ne doivent pas se retrouver dans l'argument passé
		// à ssh-keyscan.
		{"espaces autour", "  192.168.30.8:2222  ", "192.168.30.8", 2222, false},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			hote, port, err := SeparerHoteEtPort(c.cible)

			if c.doitEchouer {
				if err == nil {
					t.Fatalf("%q aurait dû être refusé, or on obtient hôte=%q port=%d", c.cible, hote, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q refusé à tort : %v", c.cible, err)
			}
			if hote != c.hote || port != c.port {
				t.Fatalf("%q → hôte=%q port=%d, attendu hôte=%q port=%d",
					c.cible, hote, port, c.hote, c.port)
			}
		})
	}
}

// TestIPv6NueNestPasDecoupee isole le piège central.
//
// Un découpage sur le dernier « : » — la première idée qui vient — donnerait
// hôte « 2001:db8: » et port « 1 ». Ce test le rendrait visible.
func TestIPv6NueNestPasDecoupee(t *testing.T) {
	hote, port, err := SeparerHoteEtPort("2001:db8::1")
	if err != nil {
		t.Fatalf("adresse IPv6 valide refusée : %v", err)
	}
	if hote != "2001:db8::1" {
		t.Fatalf("adresse tronquée : %q — un découpage sur le dernier « : » a eu lieu", hote)
	}
	if port != PortSSHParDefaut {
		t.Fatalf("port %d au lieu de %d : un morceau de l'adresse a été pris pour un port", port, PortSSHParDefaut)
	}
}

// TestPortParDefautInchange fixe la compatibilité.
//
// Toute cible écrite comme avant doit continuer de viser le port 22. Si cette
// valeur changeait, chaque « -join » existant partirait ailleurs.
func TestPortParDefautInchange(t *testing.T) {
	if PortSSHParDefaut != 22 {
		t.Fatalf("port par défaut à %d : les commandes existantes changeraient de cible", PortSSHParDefaut)
	}
	_, port, err := SeparerHoteEtPort("192.168.30.8")
	if err != nil {
		t.Fatalf("cible sans port refusée : %v", err)
	}
	if port != 22 {
		t.Fatalf("cible sans port → %d au lieu de 22", port)
	}
}
