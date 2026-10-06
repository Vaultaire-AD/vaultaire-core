package compte

import (
	"strings"
	"testing"
)

// Le nom du compte local décide de QUI ouvre la session. Ces tests gardent les
// trois propriétés dont dépend cette décision.

func TestLeNomTientDansLaBorneDeWindows(t *testing.T) {
	cas := []string{
		"a@b.fr",
		"alice@test.fr",
		"jean.dupont@acme.lan",
		"un.identifiant.vraiment.tres.long@sous.domaine.acme.lan",
		strings.Repeat("x", 200) + "@test.fr",
		"é!#$%@test.fr",
	}
	for _, u := range cas {
		n := NomLocal(u)
		if len(n) > LongueurMaxCompte {
			t.Errorf("%q -> %q : %d caractères, Windows en accepte %d", u, n, len(n), LongueurMaxCompte)
		}
		if n == "" {
			t.Errorf("%q -> nom vide", u)
		}
		if strings.HasSuffix(n, ".") {
			t.Errorf("%q -> %q : un nom de compte Windows ne peut pas finir par un point", u, n)
		}
		if i := strings.IndexAny(n, caracteresInterdits); i >= 0 {
			t.Errorf("%q -> %q : caractère interdit %q", u, n, n[i])
		}
	}
}

// Déterminisme : le même utilisateur doit retomber sur le MÊME compte à chaque
// connexion, sinon chaque ouverture de session créerait un profil neuf et
// l'utilisateur retrouverait un bureau vide.
func TestLeMemeUtilisateurDonneLeMemeCompte(t *testing.T) {
	if NomLocal("alice@test.fr") != NomLocal("alice@test.fr") {
		t.Fatal("deux appels donnent deux comptes")
	}
	// La casse ne doit pas créer un second compte : Windows ne distingue pas
	// « Alice » de « alice », et le core non plus.
	if NomLocal("Alice@Test.fr") != NomLocal("alice@test.fr") {
		t.Error("la casse crée un second compte local pour le même utilisateur")
	}
}

// Deux domaines, deux comptes : c'est tout l'intérêt du suffixe.
func TestDeuxDomainesNeSePartagentPasUnCompte(t *testing.T) {
	if NomLocal("alice@test.fr") == NomLocal("alice@autre.fr") {
		t.Fatal("alice@test.fr et alice@autre.fr partagent le même compte local")
	}
	// Et deux identifiants longs qui ne diffèrent qu'après la troncature non
	// plus — c'est le cas que la troncature seule perdrait.
	a := NomLocal("un.identifiant.tres.long.a@test.fr")
	b := NomLocal("un.identifiant.tres.long.b@test.fr")
	if a == b {
		t.Fatalf("%q : deux identifiants distincts tombent sur le même compte", a)
	}
}

// Un compte local préexistant ne doit JAMAIS être celui qu'on provisionne :
// écrire le mot de passe du domaine dans le compte « Administrateur » de la
// machine serait une prise de contrôle.
func TestLeNomNeCollePasAUnCompteLocalOrdinaire(t *testing.T) {
	for _, local := range []string{"alice", "Administrateur", "Administrator", "invite", "bob"} {
		if NomLocal(local+"@test.fr") == local {
			t.Errorf("l'utilisateur %s@test.fr reprendrait le compte local %q", local, local)
		}
	}
}
