package miseajour

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
)

func avecChemins(t *testing.T, c Chemins) {
	t.Helper()
	avant := cheminsAgent
	t.Cleanup(func() { cheminsAgent = avant })
	cheminsAgent = c
}

// Le compte rendu d'une bascule faite pendant le redémarrage part une fois,
// puis l'état est marqué rapporté.
func TestCompteRenduEnAttente(t *testing.T) {
	c := installationDeTest(t)
	if trame, _ := compteRenduEnAttente(c, "cle"); trame != "" {
		t.Fatalf("sans état : %q", trame)
	}
	_ = EcrireEtat(c, EtatFichier{Version: "2.3.1", Resultat: ResultatEchec, Motif: "revenue en arrière : x\ny"})
	trame, marquer := compteRenduEnAttente(c, "cle")
	l := strings.Split(trame, "\n")
	if len(l) != 8 || l[0] != "09_04" || l[2] != "cle" || l[5] != "2.3.1" || l[6] != ResultatEchec ||
		l[7] != "revenue en arrière : x y" {
		t.Fatalf("%q", trame)
	}
	marquer()
	if e, _ := LireEtat(c); !e.Rapporte {
		t.Fatal("non marqué rapporté")
	}
	if trame, _ := compteRenduEnAttente(c, "cle"); trame != "" {
		t.Errorf("rapporté deux fois : %q", trame)
	}
}

// Un ordre lancé ne rend pas de compte rendu immédiat.
func TestHandleTrameEnCours(t *testing.T) {
	avant := Appliquer
	t.Cleanup(func() { Appliquer = avant })
	Appliquer = func(Ordre) (string, string) { return "", "" }
	avecVersion(t, "2.3.0")
	if r := HandleTrame(storage.Trames_struct_client{Message_Order: []string{"09", "02"},
		SessionIntegritykey: "CLE", Content: "2.3.1\nreleases\nnon"}, nil); r != "" {
		t.Errorf("compte rendu immédiat : %q", r)
	}
}

func TestAppliquerHorsSystemd(t *testing.T) {
	avecChemins(t, installationDeTest(t))
	avant := systemdDirige
	t.Cleanup(func() { systemdDirige = avant })
	systemdDirige = func() bool { return false }
	if r, m := appliquerReel(Ordre{Version: "2.3.1"}); r != ResultatNonPrisEnCharge || !strings.Contains(m, "systemd") {
		t.Errorf("%s : %s", r, m)
	}
}

// Une mise à jour à la fois : le second ordre est ignoré sans compte rendu.
func TestAppliquerVerrouTenu(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("appliquerReel exige root")
	}
	c := installationDeTest(t)
	avecChemins(t, c)
	avant := systemdDirige
	t.Cleanup(func() { systemdDirige = avant })
	systemdDirige = func() bool { return true }
	if !PrendreVerrou(c, "2.3.1") {
		t.Fatal("verrou")
	}
	if r, _ := appliquerReel(Ordre{Version: "2.3.2"}); r != "" {
		t.Errorf("%q", r)
	}
	if lire(t, cheminVerrou(c)) != "2.3.1\n" {
		t.Error("verrou d'un autre repris")
	}
}

func TestLancerUpdater(t *testing.T) {
	c := installationDeTest(t)
	f := &fauxSysteme{}
	plan := Plan{Version: "2.3.1", Repertoire: filepath.Join(c.Etat, "2.3.1")}
	if err := lancerUpdater(c, plan, f.Systeme); err != nil {
		t.Fatal(err)
	}
	// L'updater est une copie de l'exécutable EN COURS.
	exe, _ := os.Executable()
	a, _ := os.ReadFile(exe)
	b, _ := os.ReadFile(c.Updater)
	if len(a) == 0 || string(a) != string(b) {
		t.Error("updater : pas une copie de l'exécutable en cours")
	}
	if !f.aAppele("systemd-run --unit=vaultaire-update --collect --quiet") ||
		!f.aAppele("restorecon -F "+c.Updater) {
		t.Fatalf("%v", f.appels)
	}
	dernier := f.appels[len(f.appels)-1]
	if !strings.HasSuffix(dernier, c.Updater+" --basculer "+plan.Repertoire) {
		t.Errorf("%q", dernier)
	}

	f.reponses = func(nom string, _ []string) ([]byte, error) {
		if nom == "systemd-run" {
			return []byte("Unit vaultaire-update.service already exists.\n"), errors.New("exit status 1")
		}
		return nil, nil
	}
	if err := lancerUpdater(c, plan, f.Systeme); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("%v", err)
	}
}

func TestExecuterUpdaterHorsDuRepertoire(t *testing.T) {
	if code := ExecuterUpdater("/tmp/ailleurs/2.3.1"); code != 2 {
		t.Errorf("code %d", code)
	}
	if code := ExecuterUpdater("/var/lib/vaultaire/updates/../../../etc"); code != 2 {
		t.Errorf("code %d", code)
	}
}

// La sonde parle le protocole du socket PAM.
func TestSondeSocket(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "pam.sock")
	l, err := net.Listen("unix", chemin)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	reponse := `{"status":"pong","version":"2.3.1","tunnel":true}`
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			var m map[string]json.RawMessage
			_ = json.NewDecoder(bufio.NewReader(conn)).Decode(&m)
			if _, ok := m["ping"]; ok {
				_, _ = conn.Write([]byte(reponse + "\n"))
			}
			_ = conn.Close()
		}
	}()
	p, err := SondeSocket(chemin)()
	if err != nil || p.Version != "2.3.1" || !p.Tunnel {
		t.Fatalf("%+v %v", p, err)
	}
	reponse = `{"status":"error","message":"requête inconnue"}`
	if _, err := SondeSocket(chemin)(); err == nil {
		t.Error("réponse d'erreur acceptée")
	}
	if _, err := SondeSocket(filepath.Join(t.TempDir(), "absent.sock"))(); err == nil {
		t.Error("socket absent accepté")
	}
}
