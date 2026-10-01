package isprotected

import (
	"testing"
	"time"
)

// Le point 96 tient à deux règles : le domaine du groupe superadmin est
// intouchable, et « intouchable » couvre ses sous-domaines. Ces tests portent
// sur la décision, pas sur la base — la lecture, elle, est éprouvée en recette.

// avecDomainesProteges force le cache, ce qui permet d'éprouver la règle sans
// base. C'est bien le comportement réel : la garde ne relit pas pendant la
// durée du cache.
func avecDomainesProteges(t *testing.T, domaines ...string) {
	t.Helper()
	domainesMu.Lock()
	domainesCache = domaines
	domainesExpire = time.Now().Add(time.Hour)
	domainesMu.Unlock()
	t.Cleanup(OublierDomainesProteges)
}

// LE test du point : le domaine du groupe superadmin et tout ce qui vit
// dessous. « Protégé dans son intégralité » n'aurait aucun sens si l'on pouvait
// créer un sous-domaine pour y travailler librement.
func TestLeDomaineProtegeCouvreSesSousDomaines(t *testing.T) {
	avecDomainesProteges(t, "vaultaire.fr")

	cas := []struct {
		domaine string
		protege bool
		motif   string
	}{
		{"vaultaire.fr", true, "le domaine lui-même"},
		{"VAULTAIRE.FR", true, "la casse ne distingue pas un domaine"},
		{"  vaultaire.fr  ", true, "les espaces non plus"},
		{"infra.vaultaire.fr", true, "un sous-domaine, sinon la protection se contourne en une commande"},
		{"a.b.vaultaire.fr", true, "à n'importe quelle profondeur"},
		{"test.fr", false, "un autre domaine reste librement administrable"},
		{"pasvaultaire.fr", false, "le suffixe doit être un SEGMENT, pas une fin de chaîne"},
		{"vaultaire.fr.example.com", false, "le domaine protégé en préfixe n'est pas le domaine protégé"},
		{"", false, "un domaine vide ne désigne rien"},
	}

	for _, c := range cas {
		if got := EstDomaineProtege(nil, c.domaine); got != c.protege {
			t.Errorf("EstDomaineProtege(%q) = %v, attendu %v — %s", c.domaine, got, c.protege, c.motif)
		}
	}
}

// Le domaine est LU en base, pas codé en dur : un annuaire peut rattacher son
// groupe superadmin à autre chose, et coder « vaultaire.fr » aurait protégé un
// domaine que personne n'utilise en laissant le vrai ouvert.
func TestLeDomaineProtegeSuitLeGroupe(t *testing.T) {
	avecDomainesProteges(t, "admin.acme.lan")

	if !EstDomaineProtege(nil, "admin.acme.lan") {
		t.Error("le domaine réellement rattaché au groupe n'est pas protégé")
	}
	if EstDomaineProtege(nil, "vaultaire.fr") {
		t.Error("un domaine d'amorçage non rattaché est protégé à tort")
	}
}

// Un groupe superadmin rattaché à plusieurs domaines : tous protégés.
func TestPlusieursDomainesSontTousProteges(t *testing.T) {
	avecDomainesProteges(t, "vaultaire.fr", "admin.acme.lan")

	for _, d := range []string{"vaultaire.fr", "admin.acme.lan", "x.admin.acme.lan"} {
		if !EstDomaineProtege(nil, d) {
			t.Errorf("%s n'est pas protégé", d)
		}
	}
}

// Sans base et sans cache, on protège quand même le domaine d'amorçage.
//
// Fail-closed : sans repli, une panne de lecture rendrait « aucun domaine
// protégé », c'est-à-dire ouvrirait exactement ce que cette garde ferme — et au
// moment où le serveur va mal.
func TestSansBaseLeDomaineDAmorcageResteProtege(t *testing.T) {
	OublierDomainesProteges()
	t.Cleanup(OublierDomainesProteges)

	if !EstDomaineProtege(nil, DomaineProtegeParDefaut) {
		t.Errorf("%s n'est pas protégé sans base : une panne de lecture ouvrirait "+
			"le domaine qui porte tous les droits", DomaineProtegeParDefaut)
	}
}

// Sans base, personne n'est superadmin — même règle que IsSuperadmin.
func TestSansBasePersonneNEstSuperadmin(t *testing.T) {
	if GroupesContiennentLeGroupeProtege(nil, []int{1, 2, 3}) {
		t.Error("appartenance accordée sans base")
	}
}

// Un appelant sans groupe n'est pas superadmin : le cas d'un compte tout neuf.
func TestAucunGroupeNEstPasSuperadmin(t *testing.T) {
	if GroupesContiennentLeGroupeProtege(nil, nil) {
		t.Error("appartenance accordée sans aucun groupe")
	}
}
