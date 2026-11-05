package miseajour

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFamilleDe(t *testing.T) {
	for osr, attendue := range map[string]string{
		"NAME=Rocky\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n": "rocky",
		"ID=debian\nVERSION_ID=\"12\"\n":                             "debian",
		"ID=ubuntu\nID_LIKE=debian\n":                                "debian",
		"VARIANT_ID=debian\nID='Rocky'\n":                            "rocky",
	} {
		if f, err := FamilleDe(osr); err != nil || f != attendue {
			t.Errorf("%q : %q %v", osr, f, err)
		}
	}
	// ID_LIKE n'est pas suivi : la règle du core (ScriptDInstallation).
	for _, osr := range []string{"ID=almalinux\nID_LIKE=\"rhel centos fedora\"\n", "NAME=x\n", ""} {
		if f, err := FamilleDe(osr); err == nil {
			t.Errorf("%q : famille %q acceptée", osr, f)
		}
	}
}

func TestRepertoirePAM(t *testing.T) {
	c := installationDeTest(t)
	if d, err := RepertoirePAM(c); err != nil || d != c.ReposPAM[0] {
		t.Fatalf("%q %v", d, err)
	}
	// Là où les modules SONT : le second candidat seul.
	c.ReposPAM = []string{filepath.Join(t.TempDir(), "vide"), c.ReposPAM[0]}
	if d, _ := RepertoirePAM(c); d != c.ReposPAM[1] {
		t.Errorf("second candidat : %q", d)
	}
	c.ReposPAM = []string{t.TempDir()}
	if _, err := RepertoirePAM(c); err == nil {
		t.Error("modules absents : pas d'erreur")
	}
}

func TestEtatAllerRetour(t *testing.T) {
	c := installationDeTest(t)
	if _, ok := LireEtat(c); ok {
		t.Fatal("état sans fichier")
	}
	if err := EcrireEtat(c, EtatFichier{Version: "2.3.1", Resultat: ResultatInstalle, Motif: "ok"}); err != nil {
		t.Fatal(err)
	}
	e, ok := LireEtat(c)
	if !ok || e.Version != "2.3.1" || e.Resultat != ResultatInstalle || e.Le.IsZero() || e.Rapporte {
		t.Fatalf("%+v %v", e, ok)
	}
	info, _ := os.Stat(cheminEtat(c))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	// Illisible : comme absent.
	ecrire(t, cheminEtat(c), "{", 0o600)
	if _, ok := LireEtat(c); ok {
		t.Error("état illisible lu")
	}
}

func TestVerrou(t *testing.T) {
	c := installationDeTest(t)
	if !PrendreVerrou(c, "2.3.1") {
		t.Fatal("premier verrou refusé")
	}
	if PrendreVerrou(c, "2.3.2") {
		t.Fatal("deuxième verrou accordé")
	}
	LibererVerrou(c)
	if !PrendreVerrou(c, "2.3.2") {
		t.Fatal("verrou rendu, puis refusé")
	}
	// Un verrou abandonné (updater tué) ne bloque pas au-delà de sa vie.
	vieux := time.Now().Add(-VieDuVerrou - time.Minute)
	_ = os.Chtimes(cheminVerrou(c), vieux, vieux)
	if !PrendreVerrou(c, "2.3.3") {
		t.Fatal("verrou abandonné toujours tenu")
	}
	if b := lire(t, cheminVerrou(c)); strings.TrimSpace(b) != "2.3.3" {
		t.Errorf("verrou : %q", b)
	}
}

func TestServiceSystemd(t *testing.T) {
	f := &fauxSysteme{reponses: func(string, []string) ([]byte, error) {
		return []byte("MainPID=4242\nActiveState=active\n"), nil
	}}
	s, err := ServiceSystemd(f.Systeme)()
	if err != nil || !s.Actif || s.PID != 4242 {
		t.Fatalf("%+v %v", s, err)
	}
	if !f.aAppele("systemctl show vaultaire_client -p ActiveState -p MainPID") {
		t.Errorf("%v", f.appels)
	}
	f.reponses = func(string, []string) ([]byte, error) { return []byte("ActiveState=activating\nMainPID=0\n"), nil }
	if s, _ := ServiceSystemd(f.Systeme)(); s.Actif {
		t.Error("activating lu comme actif")
	}
}
