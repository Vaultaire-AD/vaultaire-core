package clusterstorage

import "testing"

// L'adresse d'exposition : ce qui est accepté, ce qui prime, ce qui s'affiche.
//
// L'enjeu de ces tests n'est pas la syntaxe pour elle-même. L'adresse validée
// ici est distribuée à TOUT LE PARC par la trame 04_04, et chaque agent l'ajoute
// à sa liste de serveurs joignables. Une valeur mal formée n'est pas une erreur
// de saisie qu'on corrige à l'écran suivant : c'est une entrée que des centaines
// de machines vont tenter, échouer à joindre, et réessayer au cycle suivant.

// TestAdressesAcceptees.
func TestAdressesAcceptees(t *testing.T) {
	cas := []struct{ brut, attendu string }{
		// Vide est VALIDE : c'est ainsi qu'on retire une déclaration pour
		// revenir à l'adresse que le nœud annonce. Refuser le vide obligerait à
		// désenregistrer le nœud pour défaire une erreur de saisie.
		{"", ""},
		{"   ", ""},
		{"203.0.113.5", "203.0.113.5"},
		{"  203.0.113.5  ", "203.0.113.5"},
		{"proxy-paris.exemple.fr", "proxy-paris.exemple.fr"},
		// Le point final absolu est correct en syntaxe DNS. Le garder ferait
		// s'afficher deux valeurs distinctes pour le même nom.
		{"proxy.exemple.fr.", "proxy.exemple.fr"},
		// Une IPv6 est normalisée : net.ParseIP accepte plusieurs écritures du
		// même numéro, et les enregistrer telles que saisies ferait paraître
		// différents deux nœuds à la même adresse.
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"fd00::1", "fd00::1"},
		// Un nom d'une seule étiquette est accepté : sur un réseau à suffixe de
		// recherche, « proxy1 » résout.
		{"proxy1", "proxy1"},
	}

	for _, c := range cas {
		obtenu, err := ValiderAdressePublique(c.brut)
		if err != nil {
			t.Errorf("ValiderAdressePublique(%q) a refusé : %v", c.brut, err)
			continue
		}
		if obtenu != c.attendu {
			t.Errorf("ValiderAdressePublique(%q) = %q, attendu %q", c.brut, obtenu, c.attendu)
		}
	}
}

// TestAdressesRefusees.
func TestAdressesRefusees(t *testing.T) {
	for _, brut := range []string{
		"proxy..exemple.fr", // étiquette vide
		"-proxy.exemple.fr", // tiret en tête
		"proxy-.exemple.fr", // tiret en queue
		"proxy_paris.fr",    // souligné : jamais dans un nom d'hôte
		"http://proxy.fr",   // une URL n'est pas une adresse
		"proxy paris.fr",    // espace
		"203.0.113.5/24",    // un réseau n'est pas un hôte
	} {
		if _, err := ValiderAdressePublique(brut); err == nil {
			t.Errorf("ValiderAdressePublique(%q) a été accepté, attendu un refus", brut)
		}
	}
}

// TestLePortNEstPasAccepteDansLAdresse.
//
// Le port a son propre champ. Deux endroits pour la même information finissent
// toujours par se contredire : « 203.0.113.5:6666 » avec un port public réglé à
// 16666 ne se tranche pas. Le refus doit NOMMER le champ à employer, sinon la
// saisie la plus naturelle est rejetée sans qu'on sache par quoi la remplacer.
func TestLePortNEstPasAccepteDansLAdresse(t *testing.T) {
	for _, brut := range []string{"203.0.113.5:6666", "proxy.exemple.fr:6666", "[fd00::1]:6666"} {
		_, err := ValiderAdressePublique(brut)
		if err == nil {
			t.Errorf("ValiderAdressePublique(%q) a été accepté : le port doit aller "+
				"dans son propre champ", brut)
			continue
		}
		if !contient(err.Error(), "champ de port") {
			t.Errorf("le refus de %q n'indique pas où mettre le port : %v", brut, err)
		}
	}
}

// TestUneIPv6NueNEstPasPrisePourUnCoupleHotePort.
//
// Une IPv6 littérale est pleine de « : » sans porter de port. La confondre avec
// « hôte:port » ferait refuser la forme la plus normale d'écrire une IPv6.
func TestUneIPv6NueNEstPasPrisePourUnCoupleHotePort(t *testing.T) {
	obtenu, err := ValiderAdressePublique("fd00::1")
	if err != nil {
		t.Fatalf("une IPv6 nue a été refusée : %v", err)
	}
	if obtenu != "fd00::1" {
		t.Errorf("obtenu %q, attendu %q", obtenu, "fd00::1")
	}
}

// TestPortsAcceptesEtRefuses.
func TestPortsAcceptesEtRefuses(t *testing.T) {
	valides := []struct {
		brut    string
		attendu int
	}{
		{"", 0}, // retire la déclaration
		{"  ", 0},
		{"0", 0}, // zéro explicite : même sens que vide
		{"6666", 6666},
		{" 16666", 16666},
		{"65535", 65535},
	}
	for _, c := range valides {
		port, err := ValiderPortPublic(c.brut)
		if err != nil {
			t.Errorf("ValiderPortPublic(%q) a refusé : %v", c.brut, err)
			continue
		}
		if port != c.attendu {
			t.Errorf("ValiderPortPublic(%q) = %d, attendu %d", c.brut, port, c.attendu)
		}
	}

	for _, brut := range []string{"-1", "65536", "abc", "66 66", "6666.0"} {
		if _, err := ValiderPortPublic(brut); err == nil {
			t.Errorf("ValiderPortPublic(%q) a été accepté, attendu un refus", brut)
		}
	}
}

// TestLaDeclarationPrimeSurCeQueLeNoeudVoit.
//
// LE test de ce fichier. Un nœud derrière une redirection annonce une adresse
// privée que personne dans le parc ne peut joindre, et il n'a aucun moyen de
// s'en rendre compte : c'est tout l'objet de ces champs.
func TestLaDeclarationPrimeSurCeQueLeNoeudVoit(t *testing.T) {
	n := Node{IPAddress: "10.0.0.12", Port: 6666,
		AdressePublique: "203.0.113.5", PortPublic: 16666}

	if got := n.AdresseEffective(); got != "203.0.113.5" {
		t.Errorf("adresse effective = %q, attendu l'adresse déclarée", got)
	}
	if got := n.PortEffectif(); got != 16666 {
		t.Errorf("port effectif = %d, attendu le port déclaré", got)
	}
	if !n.ExpositionDeclaree() {
		t.Error("ExpositionDeclaree = false alors que les deux champs sont posés")
	}
}

// TestSansDeclarationOnGardeCeQueLeNoeudAnnonce.
//
// C'est la garantie de migration : une base dont les colonnes viennent d'être
// posées se comporte exactement comme avant, sans qu'aucun nœud ait à être
// touché.
func TestSansDeclarationOnGardeCeQueLeNoeudAnnonce(t *testing.T) {
	n := Node{IPAddress: "10.0.0.12", Port: 6666}

	if got := n.AdresseEffective(); got != "10.0.0.12" {
		t.Errorf("adresse effective = %q, attendu celle du nœud", got)
	}
	if got := n.PortEffectif(); got != 6666 {
		t.Errorf("port effectif = %d, attendu celui du nœud", got)
	}
	if n.ExpositionDeclaree() {
		t.Error("ExpositionDeclaree = true alors qu'aucun champ n'est posé")
	}
}

// TestLAdresseEtLePortSontIndependants.
//
// Déclarer l'un sans l'autre est un cas RÉEL, dans les deux sens : une
// redirection qui translate le port sur un hôte déjà correctement vu, ou une
// adresse publique devant un service dont le port ne bouge pas.
//
// Les lier ferait qu'un administrateur corrigeant l'adresse remettrait le port à
// la valeur interne sans l'avoir demandé.
func TestLAdresseEtLePortSontIndependants(t *testing.T) {
	portSeul := Node{IPAddress: "203.0.113.5", Port: 6666, PortPublic: 16666}
	if got := portSeul.AdresseEffective(); got != "203.0.113.5" {
		t.Errorf("adresse = %q, attendu celle du nœud", got)
	}
	if got := portSeul.PortEffectif(); got != 16666 {
		t.Errorf("port = %d, attendu le port déclaré", got)
	}
	if !portSeul.ExpositionDeclaree() {
		t.Error("un port déclaré seul doit compter comme une déclaration")
	}

	adresseSeule := Node{IPAddress: "10.0.0.12", Port: 6666, AdressePublique: "proxy.exemple.fr"}
	if got := adresseSeule.AdresseEffective(); got != "proxy.exemple.fr" {
		t.Errorf("adresse = %q, attendu celle déclarée", got)
	}
	if got := adresseSeule.PortEffectif(); got != 6666 {
		t.Errorf("port = %d, attendu celui du nœud", got)
	}
}

// TestUneAdresseFaiteDEspacesNeComptePas.
//
// Un champ de formulaire rempli d'espaces ne doit pas passer pour une
// déclaration : la vue afficherait « déclaré » sur un nœud servi à son adresse
// interne, et on chercherait longtemps pourquoi elle ne correspond pas.
func TestUneAdresseFaiteDEspacesNeComptePas(t *testing.T) {
	n := Node{IPAddress: "10.0.0.12", Port: 6666, AdressePublique: "   "}

	if got := n.AdresseEffective(); got != "10.0.0.12" {
		t.Errorf("adresse effective = %q, attendu celle du nœud", got)
	}
	if n.ExpositionDeclaree() {
		t.Error("des espaces comptent comme une déclaration")
	}
}

// TestAdresseAffichee : les crochets d'une IPv6 sont posés.
//
// « fd00::1:6666 » est illisible et ambigu ; « [fd00::1]:6666 » ne l'est pas.
// C'est aussi la forme que l'agent doit composer, donc celle qu'on veut voir
// quand on cherche pourquoi il n'y arrive pas.
func TestAdresseAffichee(t *testing.T) {
	cas := []struct {
		hote    string
		port    int
		attendu string
	}{
		{"203.0.113.5", 6666, "203.0.113.5:6666"},
		{"fd00::1", 6666, "[fd00::1]:6666"},
		{"proxy.exemple.fr", 16666, "proxy.exemple.fr:16666"},
		{"203.0.113.5", 0, "203.0.113.5"},
		{"", 6666, ""},
	}
	for _, c := range cas {
		if got := AdresseAffichee(c.hote, c.port); got != c.attendu {
			t.Errorf("AdresseAffichee(%q, %d) = %q, attendu %q", c.hote, c.port, got, c.attendu)
		}
	}
}

// contient évite d'importer strings pour une seule vérification.
func contient(s, sous string) bool {
	for i := 0; i+len(sous) <= len(s); i++ {
		if s[i:i+len(sous)] == sous {
			return true
		}
	}
	return false
}
