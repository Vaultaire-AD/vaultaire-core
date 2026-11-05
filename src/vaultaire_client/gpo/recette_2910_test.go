package gpo

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Défauts relevés par la recette GPO du 29/10 sur Rocky, Debian et Ubuntu.

func TestLeNomDuPaquetSuitLeGestionnaire(t *testing.T) {
	cas := []struct{ gestionnaire, catalogue, attendu string }{
		{"dnf", "auditd", "audit"},
		{"yum", "vim", "vim-enhanced"},
		{"dnf", "rsh-client", "rsh"},
		{"dnf", "curl", "curl"},
		{"apt", "auditd", "auditd"},
	}
	for _, c := range cas {
		if got := nomDePaquetPour(c.gestionnaire, c.catalogue); got != c.attendu {
			t.Errorf("%s/%s : %q, attendu %q", c.gestionnaire, c.catalogue, got, c.attendu)
		}
	}
}

func TestNonApplicableSeReconnaitDerriereUnMotif(t *testing.T) {
	err := fmt.Errorf("%w : SELinux absent de cette machine", ErrNonApplicable)
	if !errors.Is(err, ErrNonApplicable) {
		t.Fatal("errors.Is ne reconnaît plus ErrNonApplicable enveloppée")
	}
}

// Garde-fous de source : ces deux chemins rendaient un succès sans effet.
func TestAuditdAbsentNEstPlusUnSucces(t *testing.T) {
	if !strings.Contains(lireSource(t, "appliers_hardening.go"), "auditd absent : regle ecrite, rien n'est surveille") {
		t.Error("reloadAuditRules doit échouer quand auditd est absent")
	}
}

func TestNTPSansTimesyncdNEstPlusUnSucces(t *testing.T) {
	if strings.Contains(lireSource(t, "appliers_system.go"), `"serveurs NTP ecrits (" + servers + "), systemd-timesyncd non redemarre", nil`) {
		t.Error("applyNTPConfig rend de nouveau un succès quand timesyncd ne tourne pas")
	}
}

func TestAuditdTireSesOutilsSurRPM(t *testing.T) {
	if got := complementsRPM["auditd"]; len(got) != 1 || got[0] != "audit-rules" {
		t.Errorf("complementsRPM[auditd] = %v : sur Rocky 10 auditctl vit dans audit-rules", got)
	}
	if installerComplementsRPM("apt-get", "auditd") != "" {
		t.Error("aucun complément ne doit être tenté hors dnf/yum")
	}
}

func TestVersionMajeureDeDnf(t *testing.T) {
	for sortie, attendu := range map[string]string{
		"4.20.0\n  Installed: dnf-0:4.20.0": "4",
		"dnf5 version 5.2.6.2\ndnf5 plugin": "5",
		"":                                  "",
	} {
		if got := majeurDeVersionDnf(sortie); got != attendu {
			t.Errorf("%q : %q, attendu %q", sortie, got, attendu)
		}
	}
}

func TestDnfAutomatic4InstalleVraiment(t *testing.T) {
	c := contenuDnfAutomatic4("security")
	for _, l := range []string{"apply_updates = yes", "upgrade_type = security", "download_updates = yes"} {
		if !strings.Contains(c, l) {
			t.Errorf("configuration dnf-automatic sans %q", l)
		}
	}
}

func TestUneRegleDejaChargeeNEstPasUnEchec(t *testing.T) {
	if toleranceRegleExistante(errors.New("exit status 1 (Error sending add rule data request (Rule exists))")) != nil {
		t.Error("« Rule exists » doit être toléré")
	}
	if toleranceRegleExistante(errors.New("exit status 1 (syntax error)")) == nil {
		t.Error("une autre erreur doit remonter")
	}
}

func TestLesFichiersSystemeDUnCompteNeSontPasLusDepuisSonHome(t *testing.T) {
	sous, hors := separerSousHome([]string{
		"/home/bob/.gitconfig",
		"/etc/systemd/system/user-5007.slice.d/99-vaultaire-gpo.conf",
		"/home/bobby/x",
	}, "/home/bob")
	if len(sous) != 1 || sous[0] != "/home/bob/.gitconfig" {
		t.Errorf("sous home : %v", sous)
	}
	if len(hors) != 2 {
		t.Errorf("hors home : %v (un préfixe sans « / » final confondrait /home/bobby)", hors)
	}
}

func TestLeBusUtilisateurNEstPasInventeHorsSession(t *testing.T) {
	if p := prefixeBus("/chemin/qui/n/existe/pas"); p != nil {
		t.Errorf("préfixe %v sans répertoire d'exécution", p)
	}
	if p := prefixeBus(t.TempDir()); len(p) != 3 || p[0] != "env" {
		t.Errorf("préfixe %v", p)
	}
}

func TestUneRegleFirewalldSaitEtreInterrogee(t *testing.T) {
	q, err := requeteFirewalld(cibleFirewalld("8999/tcp", ""))
	if err != nil || len(q) != 1 || q[0] != "--query-port=8999/tcp" {
		t.Errorf("port : %v %v", q, err)
	}
	r := `rule family="ipv4" source address="10.0.0.0/8" port port="22" protocol="tcp" accept`
	q, err = requeteFirewalld(cibleFirewalld("22/tcp", r))
	if err != nil || q[0] != "--query-rich-rule="+r {
		t.Errorf("rich : %v %v", q, err)
	}
	if _, err := requeteFirewalld("8999/tcp"); err == nil {
		t.Error("une cible sans prefixe doit etre refusee")
	}
}
