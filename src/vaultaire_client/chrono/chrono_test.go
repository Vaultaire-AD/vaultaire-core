package chrono

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func journalDEssai(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), NomFichier)
	ancienC, ancienM := chemin, maintenant
	chemin = func() string { return p }
	maintenant = func() time.Time { return time.Date(2026, 10, 14, 19, 0, 1, 234_000_000, time.UTC) }
	t.Cleanup(func() { chemin, maintenant = ancienC, ancienM; Activer(false) })
	return p
}

func TestHorsDebugRienNEstEcrit(t *testing.T) {
	p := journalDEssai(t)
	Activer(false)
	Ecrire("ouverture %s", "alice@dom")
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("le journal existe hors debug (%v)", err)
	}
}

func TestEnDebugUneLigneALaMilliseconde(t *testing.T) {
	p := journalDEssai(t)
	Activer(true)
	Ecrire("ouverture %s : total %d ms", "alice@dom", 1102)
	Ecrire("fetch-key %s : %d ms", "alice@dom", 23)

	contenu, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lignes := strings.Split(strings.TrimSpace(string(contenu)), "\n")
	if len(lignes) != 2 {
		t.Fatalf("%d ligne(s), attendu 2 :\n%s", len(lignes), contenu)
	}
	if lignes[0] != "2026-10-14 19:00:01.234 ouverture alice@dom : total 1102 ms" {
		t.Errorf("ligne = %q", lignes[0])
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("droits %o, attendu 600 : le journal nomme les comptes", st.Mode().Perm())
	}
}

// Le journal est dans un répertoire de root, mais on n'écrit pas à travers un
// lien : même règle que le module PAM pour vaultaire_pam.log.
func TestUnLienNEstPasSuivi(t *testing.T) {
	p := journalDEssai(t)
	cible := filepath.Join(filepath.Dir(p), "cible")
	os.WriteFile(cible, []byte("intact\n"), 0o600)
	os.Symlink(cible, p)
	Activer(true)
	Ecrire("ouverture x")
	if c, _ := os.ReadFile(cible); string(c) != "intact\n" {
		t.Errorf("la cible du lien a été écrite : %q", c)
	}
}

func TestAuDelaDeLaBorneLAncienFichierEstGarde(t *testing.T) {
	p := journalDEssai(t)
	ancien := TailleMax
	TailleMax = 100
	t.Cleanup(func() { TailleMax = ancien })
	Activer(true)
	os.WriteFile(p, []byte(strings.Repeat("x", 200)+"\n"), 0o600)

	Ecrire("ouverture neuve")

	if c, _ := os.ReadFile(p + ".1"); !strings.HasPrefix(string(c), "xxx") {
		t.Errorf("l'ancien journal n'a pas été gardé en .1")
	}
	if c, _ := os.ReadFile(p); !strings.HasSuffix(strings.TrimSpace(string(c)), "ouverture neuve") || strings.Contains(string(c), "xxx") {
		t.Errorf("journal courant = %q", c)
	}
}
