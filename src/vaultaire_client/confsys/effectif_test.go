package confsys

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// Le contrôle ne vise que ce que le bloc demande, lu dans le bloc lui-même.
func TestAttenduVientDuBloc(t *testing.T) {
	cles, m := attenduSSHD()
	for _, c := range []string{"usepam", "kbdinteractiveauthentication", "authenticationmethods",
		"authorizedkeyscommand", "authorizedkeyscommanduser", "pubkeyauthentication"} {
		if _, ok := m[c]; !ok {
			t.Errorf("%s absent de l'attendu", c)
		}
	}
	if _, ok := m["include"]; ok || len(cles) != len(m) {
		t.Errorf("%v", cles)
	}
	if m["authorizedkeyscommand"] != "/usr/bin/vaultaire_client --fetch-key %u" {
		t.Errorf("%q", m["authorizedkeyscommand"])
	}
}

// sshd -T qui rend une valeur : remplace celle de la sortie conforme.
func sortieAvec(remplacements map[string]string) func(string, []string) ([]byte, error) {
	return func(nom string, args []string) ([]byte, error) {
		if nom != "sshd" || len(args) == 0 || args[0] != "-T" {
			return nil, nil
		}
		var out []string
		for _, l := range strings.Split(sortieSSHDTConforme, "\n") {
			k, _, _ := strings.Cut(l, " ")
			if v, ok := remplacements[k]; ok {
				if v == "" {
					continue // directive absente de cet OpenSSH
				}
				l = k + " " + v
			}
			out = append(out, l)
		}
		return []byte(strings.Join(out, "\n")), nil
	}
}

func posteInstalle(t *testing.T) poste {
	t.Helper()
	p := nouveauPoste(t, "rocky", false)
	p.installer()
	return p
}

func TestEffectifConforme(t *testing.T) {
	p := posteInstalle(t)
	f := &fauxSysteme{}
	if k := ControlerSSHDEffectif(p.env(f)); k != nil {
		t.Fatalf("%+v", k)
	}
	if !f.a("sshd -T -f " + p.chemin("etc/ssh/sshd_config")) {
		t.Errorf("%v", f.appels)
	}
}

// Une ligne remise EN TÊTE de sshd_config, avant le bloc : sshd la retient,
// le marqueur reste à jour. Écart, ligne nommée — et rien d'écrit.
func TestEffectifUneLigneAvantLeBloc(t *testing.T) {
	p := posteInstalle(t)
	avant := "UsePAM no\n" + p.lire("etc/ssh/sshd_config")
	p.ecrire("etc/ssh/sshd_config", avant)
	f := &fauxSysteme{reponses: sortieAvec(map[string]string{"usepam": "no"})}
	r := Reconcilier(p.env(f))
	if r.Etat != EtatEcart || !strings.Contains(r.Motif,
		"ssh/sshd_config (effectif) : usepam no (attendu yes) — imposé par sshd_config:1") {
		t.Fatalf("%s : %s", r.Etat, r.Motif)
	}
	if p.lire("etc/ssh/sshd_config") != avant {
		t.Error("sshd_config réécrit")
	}
	if l, _ := filepath.Glob(p.chemin("etc/ssh/*bak*")); len(l) != 0 || len(f.ecritures()) != 0 {
		t.Errorf("une écriture : %v %v", l, f.ecritures())
	}
}

// Un Include remis avant le bloc amène un fichier de sshd_config.d devant
// lui : le fichier et la ligne sont nommés.
func TestEffectifUnIncludeAvantLeBloc(t *testing.T) {
	p := posteInstalle(t)
	p.ecrire("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n"+p.lire("etc/ssh/sshd_config"))
	p.ecrire("etc/ssh/sshd_config.d/00-cloud.conf", "# cloud-init\nAuthenticationMethods publickey\n")
	f := &fauxSysteme{reponses: sortieAvec(map[string]string{"authenticationmethods": "publickey"})}
	k := ControlerSSHDEffectif(p.env(f))
	if k == nil || !strings.Contains(k.Detail, "authenticationmethods publickey (attendu publickey,keyboard-interactive)") ||
		!strings.Contains(k.Detail, "imposé par /etc/ssh/sshd_config.d/00-cloud.conf:2") {
		t.Fatalf("%+v", k)
	}
}

// Sans ligne à blâmer (un Match, une valeur par défaut) : l'écart, sans
// origine inventée.
func TestEffectifSansOrigine(t *testing.T) {
	p := posteInstalle(t)
	p.ecrire("etc/ssh/sshd_config", "Match User secours\n  X11Forwarding no\n"+p.lire("etc/ssh/sshd_config"))
	f := &fauxSysteme{reponses: sortieAvec(map[string]string{"kbdinteractiveauthentication": "no"})}
	k := ControlerSSHDEffectif(p.env(f))
	if k == nil || k.Detail != "kbdinteractiveauthentication no (attendu yes)" {
		t.Fatalf("%+v", k)
	}
}

// Une directive que cet OpenSSH n'imprime pas n'est pas un écart ; une
// valeur en majuscules non plus.
func TestEffectifToleranceDesVersions(t *testing.T) {
	p := posteInstalle(t)
	f := &fauxSysteme{reponses: sortieAvec(map[string]string{"kbdinteractiveauthentication": "", "usepam": "YES"})}
	if k := ControlerSSHDEffectif(p.env(f)); k != nil {
		t.Fatalf("%+v", k)
	}
}

func TestEffectifSSHDTRefuse(t *testing.T) {
	p := posteInstalle(t)
	f := &fauxSysteme{reponses: func(nom string, args []string) ([]byte, error) {
		return []byte("/etc/ssh/sshd_config line 3: Bad configuration option: UsePAMM\n"), errors.New("exit status 255")
	}}
	k := ControlerSSHDEffectif(p.env(f))
	if k == nil || !strings.Contains(k.Detail, "sshd -T refuse la configuration en place : /etc/ssh/sshd_config line 3") {
		t.Fatalf("%+v", k)
	}
	if !resteAFaire(Rapport{Constats: []Constat{*k}}) {
		t.Error("--config-status ne le signale pas")
	}
}

func TestEffectifAffiche(t *testing.T) {
	s := Afficher(Rapport{Constats: []Constat{{Nom: NomEffectif, Action: ActionEcartEffectif,
		Detail: "usepam no (attendu yes) — imposé par sshd_config:1"}}}, "rocky")
	if !strings.Contains(s, "ssh/sshd_config (effectif)") || !strings.Contains(s, "écart effectif — usepam no") ||
		strings.Contains(s, "attendu v0") {
		t.Errorf("%s", s)
	}
}
