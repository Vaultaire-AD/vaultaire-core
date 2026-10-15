package compte

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Le mot de passe du compte local (TO-DO 195).

func TestLeMotDePasseLocalEstLongComplexeEtNeuf(t *testing.T) {
	vus := map[string]bool{}
	for i := 0; i < 200; i++ {
		s, err := GenererMotDePasseLocal()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != LongueurMotDePasseLocal || !motDePasseComplet(s) {
			t.Fatalf("mot de passe tiré hors forme : %d caractères, complet=%v", len(s), motDePasseComplet(s))
		}
		if strings.ContainsAny(s, "\"\\\n\r ") {
			t.Fatalf("caractère à échapper dans %q", s)
		}
		if vus[s] {
			t.Fatal("deux tirages identiques")
		}
		vus[s] = true
	}
}

// Le cœur du 195 : rien n'est reposé sans raison — une remise à zéro perd les
// secrets DPAPI du compte.
func TestOnNeRemetLeMotDePasseQuAvecUneRaison(t *testing.T) {
	vrai, faux := true, false
	cas := []struct {
		nom           string
		existe, connu bool
		ouvre         *bool
		attendu       Geste
	}{
		{"compte neuf", false, false, nil, GesteCreer},
		{"compte neuf, secret déjà gardé", false, true, nil, GesteCreer},
		{"compte d'avant le 195 (mot de passe du domaine)", true, false, nil, GestePoser},
		{"secret qui ouvre : cas ordinaire", true, true, &vrai, GesteAucun},
		{"mot de passe changé hors de Vaultaire", true, true, &faux, GestePoser},
		{"vérification non concluante", true, true, nil, GesteAucun},
	}
	for _, c := range cas {
		if got := decider(c.existe, c.connu, c.ouvre); got != c.attendu {
			t.Errorf("%s : geste %d, attendu %d", c.nom, got, c.attendu)
		}
	}
}

func avecGardeSimulee(t *testing.T) string {
	t.Helper()
	dossier, ancienP, ancienD := DossierSecrets, proteger, deproteger
	t.Cleanup(func() { DossierSecrets, proteger, deproteger = dossier, ancienP, ancienD })
	DossierSecrets = filepath.Join(t.TempDir(), "comptes")
	brouiller := func(b []byte) ([]byte, error) {
		out := make([]byte, len(b))
		for i := range b {
			out[i] = b[i] ^ 0x5a
		}
		return out, nil
	}
	proteger, deproteger = brouiller, brouiller
	return DossierSecrets
}

func TestLeSecretSeGardeChiffreEtSeRelit(t *testing.T) {
	dossier := avecGardeSimulee(t)
	if _, connu, err := LireSecret("alice-1f4b2c"); err != nil || connu {
		t.Fatalf("secret absent : connu=%v err=%v", connu, err)
	}
	s, _ := GenererMotDePasseLocal()
	if err := EcrireSecret("alice-1f4b2c", s); err != nil {
		t.Fatal(err)
	}
	brut, err := os.ReadFile(filepath.Join(dossier, "alice-1f4b2c.secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(brut, []byte(s)) {
		t.Error("le secret est écrit en clair")
	}
	relu, connu, err := LireSecret("alice-1f4b2c")
	if err != nil || !connu || relu != s {
		t.Fatalf("relecture : connu=%v err=%v égal=%v", connu, err, relu == s)
	}
	if _, err := os.Stat(filepath.Join(dossier, "alice-1f4b2c.secret.nouveau")); !os.IsNotExist(err) {
		t.Error("le fichier provisoire est resté")
	}
}

func TestUnSecretAbimeNEstPasPrisPourLeBon(t *testing.T) {
	dossier := avecGardeSimulee(t)
	if err := os.MkdirAll(dossier, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dossier, "bob-000000.secret"), []byte("tronqué"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, connu, err := LireSecret("bob-000000"); err == nil || connu {
		t.Errorf("secret tronqué accepté : connu=%v err=%v", connu, err)
	}
}

func TestLeNomNeSortPasDuDossier(t *testing.T) {
	avecGardeSimulee(t)
	for _, nom := range []string{"../x", `a\b`, "..", "", "UN-NOM-EN-MAJ", "plus-de-vingt-caracteres"} {
		if err := EcrireSecret(nom, "x"); err == nil {
			t.Errorf("nom %q accepté", nom)
		}
	}
	// Un vrai nom local passe.
	if _, err := cheminSecret(NomLocal("jean.dupont@acme.lan")); err != nil {
		t.Errorf("nom local refusé : %v", err)
	}
}
