package ipc

import (
	"bytes"
	"strings"
	"testing"
)

// Le mot de passe en clair de chaque connexion passe par ce canal, et ce qui en
// sort part dans une trame dont les champs sont séparés par des sauts de ligne.
// Ces tests gardent les deux bornes : ce qu'on accepte, et ce qu'on lit.

func TestUnSautDeLigneEstRefuse(t *testing.T) {
	cas := []Requete{
		{Type: TypeAuth, Utilisateur: "alice@test.fr", MotDePasse: "abc\ndef"},
		{Type: TypeAuth, Utilisateur: "alice@test.fr", MotDePasse: "abc\rdef"},
		{Type: TypeAuth, Utilisateur: "alice\n@test.fr", MotDePasse: "abc"},
	}
	for _, r := range cas {
		if err := ValiderRequete(r); err == nil {
			t.Errorf("accepté : %q / %q — les champs de la trame 03_01 seraient décalés",
				r.Utilisateur, r.MotDePasse)
		}
	}
}

func TestUnNomValideEstAccepte(t *testing.T) {
	for _, nom := range []string{"alice@test.fr", "a.b-c_d@sous.domaine.fr", "bob"} {
		if err := ValiderRequete(Requete{Type: TypeAuth, Utilisateur: nom, MotDePasse: "x"}); err != nil {
			t.Errorf("%q refusé : %v", nom, err)
		}
	}
}

func TestCeQuiEstRefuseSansMotDePasse(t *testing.T) {
	if err := ValiderRequete(Requete{Type: TypeAuth, Utilisateur: "alice@test.fr"}); err == nil {
		t.Error("requête sans mot de passe acceptée")
	}
	// L'état, lui, n'en demande pas : il sert justement à répondre avant que
	// l'utilisateur ait tapé quoi que ce soit.
	if err := ValiderRequete(Requete{Type: TypeEtat}); err != nil {
		t.Errorf("requête d'état refusée : %v", err)
	}
}

func TestUnTypeInconnuEstRefuse(t *testing.T) {
	if err := ValiderRequete(Requete{Type: "sudo", Utilisateur: "a", MotDePasse: "b"}); err == nil {
		t.Error("type inconnu accepté")
	}
}

func TestUnNomDemesureEstRefuse(t *testing.T) {
	long := strings.Repeat("a", LongueurMaxNom+1)
	if err := ValiderRequete(Requete{Type: TypeAuth, Utilisateur: long, MotDePasse: "x"}); err == nil {
		t.Error("nom démesuré accepté")
	}
}

// La lecture est BORNÉE : un appelant local qui enverrait un flux sans fin ferait
// monter la mémoire de l'agent jusqu'à sa mort — et l'écran de connexion de la
// machine n'aurait plus personne pour lui répondre.
func TestLaLectureEstBornee(t *testing.T) {
	enorme := `{"type":"auth","user":"a","password":"` + strings.Repeat("x", TailleMaxRequete*2) + `"}`
	if _, err := LireRequete(strings.NewReader(enorme)); err == nil {
		t.Fatal("requête au-delà de la borne acceptée")
	}
}

func TestUnAllerRetourSeRelit(t *testing.T) {
	var tampon bytes.Buffer
	if err := EcrireReponse(&tampon, Reponse{
		Statut: StatutSucces, Administrateur: true, CompteLocal: "alice.test.fr",
	}); err != nil {
		t.Fatal(err)
	}
	// Une seule ligne : le lecteur C++ n'a pas d'analyseur JSON en flux.
	if bytes.Count(tampon.Bytes(), []byte("\n")) != 1 || !bytes.HasSuffix(tampon.Bytes(), []byte("\n")) {
		t.Fatalf("réponse %q : attendu une seule ligne terminée par un saut de ligne", tampon.String())
	}
	for _, attendu := range []string{`"status":"success"`, `"is_admin":true`, `"local_account":"alice.test.fr"`} {
		if !strings.Contains(tampon.String(), attendu) {
			t.Errorf("réponse %q : %s manquant", tampon.String(), attendu)
		}
	}
}

// Un refus ne dit PAS pourquoi : le motif exact appartient au core, qui le
// journalise. Le dire à l'écran de connexion renseignerait qui essaie des mots
// de passe sur l'existence du compte.
func TestUnRefusNeDetaillePasLeMotif(t *testing.T) {
	var tampon bytes.Buffer
	if err := EcrireReponse(&tampon, Reponse{Statut: StatutRefus}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tampon.String(), "is_admin") || strings.Contains(tampon.String(), "local_account") {
		t.Errorf("réponse de refus %q : elle porte des champs de succès", tampon.String())
	}
}
