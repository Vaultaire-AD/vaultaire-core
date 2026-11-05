package gpo

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TO-DO 182 : la configuration SSH EN VIGUEUR, pas le fragment.

// avecSSHDT remplace sshd -T par une sortie fixe, le temps d'un test.
func avecSSHDT(t *testing.T, sortie string, errSSHD error) {
	t.Helper()
	runAvant, existeAvant := runCommand, commandExists
	t.Cleanup(func() { runCommand, commandExists = runAvant, existeAvant })
	commandExists = func(string) bool { return true }
	runCommand = func(name string, args ...string) (string, error) {
		if name == "sshd" && len(args) == 1 && args[0] == "-T" {
			return sortie, errSSHD
		}
		return "", nil
	}
}

func TestLAttenteSSHDPorteLesNomsDeSshdT(t *testing.T) {
	obtenu := attenteSSHD([]string{"MaxAuthTries 3", "Banner /etc/ssh/vaultaire-banner",
		"PermitRootLogin without-password", "PasswordAuthentication  No"})
	attendu := "banner=/etc/ssh/vaultaire-banner,maxauthtries=3,passwordauthentication=no,permitrootlogin=prohibit-password"
	if obtenu != attendu {
		t.Errorf("attente = %q\n          attendu %q", obtenu, attendu)
	}
}

// LE CONSTAT DE LA RECETTE : MaxAuthTries 10 en tête de sshd_config, la
// politique en demande 3, le fragment est intact.
func TestUneDirectiveMasqueeEstUnEcart(t *testing.T) {
	avecSSHDT(t, "port 22\nmaxauthtries 10\nbanner none\npermitrootlogin without-password\n", nil)
	ok, detail, err := verifierSSHEffectif(SystemCheck{Kind: CheckSSHEffectif, Target: "sshd",
		Expect: "banner=/etc/ssh/vaultaire-banner,maxauthtries=3,permitrootlogin=prohibit-password"})
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v : attendu un écart", ok, err)
	}
	for _, morceau := range []string{"sshd maxauthtries : 3 attendu, 10 constate",
		"sshd banner : /etc/ssh/vaultaire-banner attendu, none constate", "l'emporte"} {
		if !strings.Contains(detail, morceau) {
			t.Errorf("détail sans %q : %s", morceau, detail)
		}
	}
	if strings.Contains(detail, "permitrootlogin") {
		t.Errorf("without-password vaut prohibit-password, pas un écart : %s", detail)
	}
}

func TestUneConfigurationAppliqueeEstConforme(t *testing.T) {
	avecSSHDT(t, "MaxAuthTries 3\nbanner /etc/ssh/vaultaire-banner\n", nil)
	ok, detail, err := verifierSSHEffectif(SystemCheck{Expect: "banner=/etc/ssh/vaultaire-banner,maxauthtries=3"})
	if !ok || err != nil {
		t.Errorf("ok=%v detail=%q err=%v : attendu conforme", ok, detail, err)
	}
}

// Une directive que sshd ne rend pas du tout n'est pas appliquée.
func TestUneDirectiveAbsenteEstUnEcart(t *testing.T) {
	avecSSHDT(t, "port 22\n", nil)
	ok, detail, _ := verifierSSHEffectif(SystemCheck{Expect: "clientaliveinterval=300"})
	if ok || !strings.Contains(detail, "absente constate") {
		t.Errorf("ok=%v detail=%q", ok, detail)
	}
}

// sshd -T en échec : on ne sait pas — incertitude, jamais « conforme » ni écart.
func TestSshdTIllisibleEstUneIncertitude(t *testing.T) {
	avecSSHDT(t, "", errors.New("sshd: no hostkeys available"))
	ok, _, err := verifierSSHEffectif(SystemCheck{Expect: "maxauthtries=3"})
	if ok || err == nil {
		t.Errorf("ok=%v err=%v : attendu une erreur (incertitude)", ok, err)
	}
}

// Le fragment doit passer AVANT les fragments des distributions : sshd
// retient la première valeur lue.
func TestLeFragmentSSHPasseAvantCeuxDesDistributions(t *testing.T) {
	nom := filepath.Base(sshFragmentPath)
	for _, autre := range []string{"01-permitrootlogin.conf", "40-redhat-crypto-policies.conf",
		"50-cloud-init.conf", "50-redhat.conf"} {
		if nom >= autre {
			t.Errorf("%s est lu après %s : il serait masqué", nom, autre)
		}
	}
}

// Un module SSH appliqué par un agent d'avant le 182 manque de son attente ;
// une fois inscrite, plus.
func TestUnModuleSSHSansAttenteEstRepere(t *testing.T) {
	m := Module{Type: ModuleSSHServerConfig, StateKey: "ssh:1", Fingerprint: "fp"}
	ancien := &ScopeState{Modules: map[string]string{"ssh:1": "fp"}}
	if !attenteManquante(m, ancien) {
		t.Error("état d'avant le 182 : le module devrait être rejoué")
	}
	ancien.Checks = map[string]SystemCheck{"x": {Kind: CheckSSHEffectif, Target: "sshd", StateKey: "ssh:1"}}
	if attenteManquante(m, ancien) {
		t.Error("attente inscrite : le module ne doit plus être rejoué")
	}
	autre := Module{Type: ModuleSysctl, StateKey: "k", Fingerprint: "fp"}
	if attenteManquante(autre, &ScopeState{}) {
		t.Error("un module sans attente exigée n'est jamais rejoué pour ça")
	}
}

// Le rattrapage INSCRIT l'attente sans rejouer le module : aucune commande,
// aucun fichier — en audit, rejouer corrigerait la dérive.
func TestLAttenteDUnModuleAncienEstInscriteSansLeRejouer(t *testing.T) {
	runAvant, existeAvant := runCommand, commandExists
	t.Cleanup(func() { runCommand, commandExists = runAvant, existeAvant })
	commandExists = func(string) bool { return true }
	runCommand = func(name string, args ...string) (string, error) {
		t.Errorf("commande lancee pendant le rattrapage : %s %v", name, args)
		return "", nil
	}

	m := Module{Type: ModuleSSHServerConfig, Scope: ScopeMachine, StateKey: "ssh_server_config:-",
		Fingerprint: "fp-ssh", Params: map[string]string{"max_auth_tries": "3", "permit_root_login": "unchanged"}}
	politique := &Policy{Name: "p", Scope: ScopeMachine, Version: 2, Fingerprint: "pol", Modules: []Module{m}}
	ancien := &ScopeState{Fingerprint: "", Modules: map[string]string{m.StateKey: "fp-ssh"}}

	rapport := ApplyPolicy(politique, ancien)
	if rapport.Modules[0].Result != ResultUnchanged {
		t.Fatalf("resultat = %s, attendu inchange", rapport.Modules[0].Result)
	}
	etat := BuildScopeState(politique, ancien, rapport)
	if etat.manqueAttente(m.Type, m.StateKey) {
		t.Fatalf("attente non inscrite : %+v", etat.Checks)
	}
	for _, c := range etat.Checks {
		if c.Kind == CheckSSHEffectif && c.Expect != "maxauthtries=3" {
			t.Errorf("attente = %q, attendu maxauthtries=3", c.Expect)
		}
	}
}

// TO-DO 246 : le client ssh, par `ssh -G` sur la seule configuration système.
func TestLeClientSSHMasqueEstUnEcart(t *testing.T) {
	runAvant, existeAvant := runCommand, commandExists
	t.Cleanup(func() { runCommand, commandExists = runAvant, existeAvant })
	commandExists = func(string) bool { return true }
	var vu []string
	runCommand = func(name string, args ...string) (string, error) {
		vu = append([]string{name}, args...)
		return "user root\nstricthostkeychecking false\nport 22\n", nil
	}
	ok, detail, err := verifierSSHClientEffectif(SystemCheck{Expect: "stricthostkeychecking=yes"})
	if ok || err != nil || !strings.Contains(detail, "ssh stricthostkeychecking : yes attendu, no constate") {
		t.Fatalf("ok=%v err=%v detail=%q", ok, err, detail)
	}
	if strings.Join(vu, " ") != "ssh -F /etc/ssh/ssh_config -G vaultaire-verification.invalid" {
		t.Errorf("commande = %v : la configuration de root ne doit pas entrer en compte", vu)
	}
	runCommand = func(string, ...string) (string, error) { return "stricthostkeychecking true\n", nil }
	if ok, _, _ := verifierSSHClientEffectif(SystemCheck{Expect: "stricthostkeychecking=yes"}); !ok {
		t.Error("true (ssh -G) et yes (politique) sont la même valeur")
	}
}

func TestLeFragmentClientSSHPasseAvantCeuxDesDistributions(t *testing.T) {
	nom := filepath.Base(sshClientDropIn)
	for _, autre := range []string{"05-redhat.conf", "50-redhat.conf", "20-systemd-ssh-proxy.conf"} {
		if nom >= autre {
			t.Errorf("%s est lu après %s : il serait masqué", nom, autre)
		}
	}
}
