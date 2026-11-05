package localusermanagement

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Le droit d'administration, géré par l'agent seul — TO-DO 197.

func TestUnAdministrateurEstInscritDansSudoSurDebian(t *testing.T) {
	group := machineSimulee(t, "root:x:0:\nsudo:x:27:\nalice:x:5001:\n")

	g, change, err := AppliquerDroitAdministration("alice", true)
	if err != nil || g != "sudo" || !change {
		t.Fatalf("(%q, %v, %v), attendu (sudo, true, nil)", g, change, err)
	}
	if m := membresDe(t, group, "sudo"); len(m) != 1 || m[0] != "alice" {
		t.Errorf("membres de sudo = %v", m)
	}
}

// L'agent ne connaissait que wheel : sur Rocky, c'est lui qui doit servir.
func TestUnAdministrateurEstInscritDansWheelSurRocky(t *testing.T) {
	group := machineSimulee(t, "root:x:0:\nwheel:x:10:\n")

	g, _, err := AppliquerDroitAdministration("alice", true)
	if err != nil || g != "wheel" {
		t.Fatalf("(%q, %v), attendu wheel", g, err)
	}
	if m := membresDe(t, group, "wheel"); len(m) != 1 || m[0] != "alice" {
		t.Errorf("membres de wheel = %v", m)
	}
}

// Le défaut de l'agent : un compte qui perd son droit dans l'annuaire le
// gardait sur la machine.
func TestUnCompteQuiNEstPlusAdministrateurEstRetire(t *testing.T) {
	group := machineSimulee(t, "wheel:x:10:bob,alice,carol\n")

	g, change, err := AppliquerDroitAdministration("alice", false)
	if err != nil || g != "wheel" || !change {
		t.Fatalf("(%q, %v, %v), attendu (wheel, true, nil)", g, change, err)
	}
	m := membresDe(t, group, "wheel")
	if strings.Join(m, ",") != "bob,carol" {
		t.Errorf("membres de wheel = %v, attendu bob,carol — les autres ne bougent pas", m)
	}
}

// Le défaut du module : usermod ou gpasswd à CHAQUE connexion. Rien ne doit
// être réécrit quand l'appartenance est déjà la bonne.
func TestRienNEstReecritQuandRienNeChange(t *testing.T) {
	for _, cas := range []struct {
		nom     string
		contenu string
		admin   bool
	}{
		{"administrateur déjà membre", "wheel:x:10:alice\n", true},
		{"compte ordinaire déjà absent", "wheel:x:10:bob\n", false},
	} {
		t.Run(cas.nom, func(t *testing.T) {
			group := machineSimulee(t, cas.contenu)
			// Une date ancienne et fixe : une réécriture, même du même
			// contenu, la remplacerait par l'heure courante.
			ancienne := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			if err := os.Chtimes(group, ancienne, ancienne); err != nil {
				t.Fatal(err)
			}

			_, change, err := AppliquerDroitAdministration("alice", cas.admin)
			if err != nil || change {
				t.Fatalf("(%v, %v), attendu (false, nil)", change, err)
			}
			if st, _ := os.Stat(group); !st.ModTime().Equal(ancienne) {
				t.Errorf("/etc/group a été réécrit alors que rien ne changeait")
			}
		})
	}
}

func TestSudoPasseAvantWheel(t *testing.T) {
	machineSimulee(t, "wheel:x:10:\nsudo:x:27:\n")
	if g, err := GroupeAdministration(); err != nil || g != "sudo" {
		t.Errorf("(%q, %v), attendu sudo", g, err)
	}
}

// staff et root, que le module essayait, ne donnent pas sudo : jamais pris.
func TestStaffEtRootNeSontPasDesGroupesDAdministration(t *testing.T) {
	group := machineSimulee(t, "root:x:0:\nstaff:x:50:\n")

	_, change, err := AppliquerDroitAdministration("alice", true)
	if err == nil || change {
		t.Fatalf("(%v, %v), attendu une erreur qui dit qu'aucun groupe n'existe", change, err)
	}
	contenu, _ := os.ReadFile(group)
	if strings.Contains(string(contenu), "alice") {
		t.Errorf("alice a été inscrite quelque part :\n%s", contenu)
	}
	// Et aucun groupe n'est créé.
	if strings.Contains(string(contenu), "sudo") {
		t.Errorf("un groupe sudo a été créé :\n%s", contenu)
	}
}

// Sans groupe d'administration, un compte ordinaire n'a rien à faire : pas
// d'erreur à chaque connexion.
func TestSansGroupeUnCompteOrdinaireNeSignaleRien(t *testing.T) {
	machineSimulee(t, "root:x:0:\n")
	if _, _, err := AppliquerDroitAdministration("alice", false); err != nil {
		t.Errorf("erreur %v pour un compte ordinaire sans groupe d'administration", err)
	}
}

func TestUnNomQuiCasseLeFichierEstRefuse(t *testing.T) {
	group := machineSimulee(t, "wheel:x:10:\n")
	for _, nom := range []string{"", "a:b", "a,root", "a b", "a\nroot:x:0:"} {
		if _, _, err := AppliquerDroitAdministration(nom, true); err == nil {
			t.Errorf("nom %q accepté", nom)
		}
	}
	if m := membresDe(t, group, "wheel"); len(m) != 0 {
		t.Errorf("wheel a reçu des membres : %v", m)
	}
}

// ---------------------------------------------------------------------------
// SELinux : tout le dossier à la création, le strict nécessaire ensuite.
// ---------------------------------------------------------------------------

func espionRestorecon(t *testing.T, absent bool) *[]string {
	t.Helper()
	var appels []string
	ancien := lancerRestorecon
	lancerRestorecon = func(args ...string) ([]byte, error) {
		if absent {
			return nil, errRestoreconAbsent
		}
		appels = append(appels, strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { lancerRestorecon = ancien })
	return &appels
}

func TestALaCreationToutLeDossierEstRelabellise(t *testing.T) {
	appels := espionRestorecon(t, false)
	RestaurerContexteSELinux("/home/alice")
	if strings.Join(*appels, "|") != "-RF /home/alice" {
		t.Errorf("appels = %v", *appels)
	}
}

// Le coût relevé par le 190 : un parcours complet du HOME à chaque connexion.
func TestAUneConnexionSeulsLeDossierEtSshSontRelabellises(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	appels := espionRestorecon(t, false)

	RestaurerContexteSELinuxCompte(home)

	attendu := "-F " + home + "|-RF " + filepath.Join(home, ".ssh")
	if strings.Join(*appels, "|") != attendu {
		t.Errorf("appels = %v, attendu %s", *appels, attendu)
	}
	for _, a := range *appels {
		if strings.HasPrefix(a, "-RF ") && strings.TrimPrefix(a, "-RF ") == home {
			t.Errorf("le dossier entier est encore parcouru : %q", a)
		}
	}
}

func TestSansSshSeulLeDossierEstRelabellise(t *testing.T) {
	home := t.TempDir()
	appels := espionRestorecon(t, false)
	RestaurerContexteSELinuxCompte(home)
	if strings.Join(*appels, "|") != "-F "+home {
		t.Errorf("appels = %v", *appels)
	}
}

func TestSansSELinuxRienNEstLanceNiSignale(t *testing.T) {
	home := t.TempDir()
	os.Mkdir(filepath.Join(home, ".ssh"), 0o700)
	appels := espionRestorecon(t, true)
	RestaurerContexteSELinuxCompte(home)
	if len(*appels) != 0 {
		t.Errorf("appels = %v", *appels)
	}
}
