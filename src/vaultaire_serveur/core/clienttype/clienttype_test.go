package clienttype

import (
	"regexp"
	"testing"
)

// TestFailClosed est le test qui compte. Le catalogue est une frontière de
// privilège : ce qui n'est pas déclaré doit être refusé, y compris ce à quoi
// personne n'a pensé.
func TestFailClosed(t *testing.T) {
	cases := []struct{ clientType, frame string }{
		{"", "01_01"},
		{"inconnu", "01_01"},
		{"VAULTAIRE_CLIENT", "01_01"}, // la casse n'est pas une orthographe valide
		{Client, "99_99"},             // catégorie qui n'existe pas
		{Client, ""},
		{Client, "07_01"}, // un agent ne relaie pas de commandes
		{Web, "05_01"},    // le web ne demande pas de GPO
		{Web, "06_02"},    // ni n'acquitte de révocation
		{Web, "02_12"},    // ni ne déclare d'inventaire matériel
		{Web, "02_13"},    //
		{Proxy, "07_01"},  // le proxy ne relaie pas de commandes
		{Proxy, "02_01"},  // et n'authentifie personne
		{Client, "04_01"}, // un agent n'est pas un hôte du cluster
		{Client, "02_13"}, // l'agent émet 02_12, jamais 02_13
		{Client, "01_03"}, // un agent ne s'enrôle pas : il est créé sur le core
	}
	for _, c := range cases {
		if MayEmit(c.clientType, c.frame) {
			t.Errorf("MayEmit(%q, %q) = true, attendu false", c.clientType, c.frame)
		}
	}
}

// TestMayEmitAllowed vérifie que ce qui est déclaré passe.
func TestMayEmitAllowed(t *testing.T) {
	cases := []struct{ clientType, frame string }{
		{Client, "01_01"}, {Client, "02_01"}, {Client, "05_01"}, {Client, "06_04"},
		{Client, "02_12"},
		{Proxy, "04_01"}, {Proxy, "04_07"},
		{Web, "07_01"}, {Web, "02_01"}, {Web, "04_09"},
	}
	for _, c := range cases {
		if !MayEmit(c.clientType, c.frame) {
			t.Errorf("MayEmit(%q, %q) = false, attendu true", c.clientType, c.frame)
		}
	}
}

// TestAssertUserIsRare : le droit de parler au nom d'un tiers est le privilège
// le plus lourd du catalogue. S'il s'étend, c'est une décision, pas un accident.
func TestAssertUserIsRare(t *testing.T) {
	var porteurs []string
	for _, d := range All() {
		if d.AssertsUser {
			porteurs = append(porteurs, d.Name)
		}
	}
	if len(porteurs) != 1 || porteurs[0] != Web {
		t.Errorf("AssertsUser porté par %v, attendu uniquement [%s]", porteurs, Web)
	}
}

// TestServiceNamesAreServices : une clé d'enrôlement ne vise qu'un service.
// Un agent se crée sur le core, il n'a rien à enrôler.
func TestServiceNamesAreServices(t *testing.T) {
	for _, name := range ServiceNames() {
		if !IsService(name) {
			t.Errorf("%s listé comme service mais IsService = false", name)
		}
	}
	if IsService(Client) {
		t.Error("un agent ne doit pas être considéré comme un service")
	}
}

// TestCatalogueWellFormed attrape les fautes de frappe dans les listes de
// trames, qui sinon ne se verraient qu'en production sous la forme d'un client
// qui ne peut plus rien émettre.
func TestCatalogueWellFormed(t *testing.T) {
	frameRe := regexp.MustCompile(`^\d{2}_\d{2}$`)
	seen := map[string]bool{}

	for _, d := range All() {
		if seen[d.Name] {
			t.Errorf("type %s déclaré deux fois", d.Name)
		}
		seen[d.Name] = true

		if d.Family != FamilyAgent && d.Family != FamilyService {
			t.Errorf("%s : famille %q inconnue", d.Name, d.Family)
		}
		if len(d.Frames) == 0 {
			t.Errorf("%s : aucune trame déclarée", d.Name)
		}

		dup := map[string]bool{}
		for _, f := range d.Frames {
			if !frameRe.MatchString(f) {
				t.Errorf("%s : trame %q malformée, attendu CC_SS", d.Name, f)
			}
			if dup[f] {
				t.Errorf("%s : trame %q listée deux fois", d.Name, f)
			}
			dup[f] = true
		}

		// Tout le monde doit pouvoir ouvrir une session, sinon le type est
		// inutilisable.
		if !MayEmit(d.Name, "01_01") {
			t.Errorf("%s : ne peut pas émettre 01_01, il ne pourra jamais se connecter", d.Name)
		}

		// Seul un service s'enrôle. Un agent qui porterait 01_03 pourrait
		// contourner la création côté core.
		if MayEmit(d.Name, "01_03") && d.Family != FamilyService {
			t.Errorf("%s : agent autorisé à s'enrôler (01_03)", d.Name)
		}

		// Le relais de commandes n'a de sens qu'avec l'assertion d'identité.
		if MayEmit(d.Name, "07_01") && !d.AssertsUser {
			t.Errorf("%s : émet 07_01 sans AssertsUser", d.Name)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(Web); err != nil {
		t.Errorf("Validate(%s) = %v, attendu nil", Web, err)
	}
	if err := Validate("nimporte_quoi"); err == nil {
		t.Error("Validate a accepté un type inconnu")
	}
}
