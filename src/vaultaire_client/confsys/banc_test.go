package confsys

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Le banc : un poste d'essai, ses fichiers d'origine, et les deux scripts
// d'installation joués à blanc (VAULTAIRE_RACINE) — les mêmes que ceux de
// controle/rocky_test.go et debian_test.go.

const dossierScripts = "../../../automatisation/auto_deployements/"

const (
	origLoginRocky = "#%PAM-1.0\nauth       substack     system-auth\nauth       include      postlogin\n" +
		"account    required     pam_nologin.so\naccount    include      system-auth\npassword   include      system-auth\n" +
		"session    include      system-auth\nsession    include      postlogin\n"
	origSSHDRocky = "#%PAM-1.0\nauth       substack     password-auth\nauth       include      postlogin\n" +
		"account    required     pam_nologin.so\naccount    include      password-auth\nsession    include      password-auth\n"
	origGDMRocky        = "#%PAM-1.0\nauth     substack       password-auth\nsession  include        password-auth\n"
	origSSHDConfigRocky = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nUsePAM yes\n" +
		"Subsystem\tsftp\t/usr/libexec/openssh/sftp-server\n"
	origNSS = "passwd:     sss files systemd\ngroup:      sss files systemd\nshadow:     files\nhosts:      files dns myhostname\n"

	origLoginDebian = "#\n# The PAM configuration file for the Shadow 'login' service\n#\n" +
		"auth       optional   pam_faildelay.so  delay=3000000\nauth       requisite  pam_nologin.so\n" +
		"session    required     pam_loginuid.so\n\n# Standard Un*x authentication.\n@include common-auth\n\n" +
		"auth       optional   pam_group.so\nsession    required   pam_limits.so\n@include common-account\n" +
		"@include common-session\n@include common-password\n"
	origSSHDDebian = "# PAM configuration for the Secure Shell service\n\n# Standard Un*x authentication.\n" +
		"@include common-auth\n\naccount    required     pam_nologin.so\n@include common-account\n" +
		"session    required     pam_loginuid.so\n@include common-session\nsession    required     pam_limits.so\n" +
		"@include common-password\n"
	origGDMDebian = "#%PAM-1.0\nauth    requisite       pam_nologin.so\n" +
		"auth    required        pam_succeed_if.so user != root quiet_success\n@include common-auth\n" +
		"auth    optional        pam_gnome_keyring.so\n@include common-account\nsession required        pam_loginuid.so\n" +
		"@include common-session\nsession optional        pam_gnome_keyring.so auto_start\n@include common-password\n"
	origSSHDConfigDebian = "Include /etc/ssh/sshd_config.d/*.conf\n\n#PubkeyAuthentication yes\n" +
		"KbdInteractiveAuthentication no\nUsePAM yes\nX11Forwarding yes\nSubsystem\tsftp\t/usr/lib/openssh/sftp-server\n"
)

type poste struct {
	t       *testing.T
	racine  string
	famille string
	pam     string
	origine map[string]string // rel → contenu d'avant l'installation
}

func (p poste) chemin(rel string) string { return filepath.Join(p.racine, rel) }

func (p poste) ecrire(rel, contenu string) {
	p.t.Helper()
	if err := os.MkdirAll(filepath.Dir(p.chemin(rel)), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(p.chemin(rel), []byte(contenu), 0o644); err != nil {
		p.t.Fatal(err)
	}
}

func (p poste) lire(rel string) string {
	p.t.Helper()
	b, err := os.ReadFile(p.chemin(rel))
	if err != nil {
		p.t.Fatalf("%s : %v", rel, err)
	}
	return string(b)
}

// nouveauPoste monte un poste de la famille, avec GDM ou non.
func nouveauPoste(t *testing.T, famille string, gdm bool) poste {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("les scripts d'installation ne se jouent que sous Linux")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash absent")
	}
	p := poste{t: t, racine: t.TempDir(), famille: famille, origine: map[string]string{}}
	if famille == "rocky" {
		p.pam = "usr/lib64/security"
		p.origine["etc/pam.d/login"] = origLoginRocky
		p.origine["etc/pam.d/sshd"] = origSSHDRocky
		p.origine["etc/ssh/sshd_config"] = origSSHDConfigRocky
		if gdm {
			p.origine["etc/pam.d/gdm-password"] = origGDMRocky
		}
		p.ecrire("etc/os-release", "NAME=\"Rocky Linux\"\nID=\"rocky\"\n")
	} else {
		p.pam = "lib/x86_64-linux-gnu/security"
		p.origine["etc/pam.d/login"] = origLoginDebian
		p.origine["etc/pam.d/sshd"] = origSSHDDebian
		p.origine["etc/ssh/sshd_config"] = origSSHDConfigDebian
		if gdm {
			p.origine["etc/pam.d/gdm-password"] = origGDMDebian
		}
		p.ecrire("etc/os-release", "ID=debian\n")
	}
	p.origine["etc/nsswitch.conf"] = origNSS
	for rel, c := range p.origine {
		p.ecrire(rel, c)
	}
	p.ecrire(p.pam+"/pam_unix.so", "")
	p.ecrire("etc/ssh/sshd_config.d/50-distribution.conf", "PasswordAuthentication yes\n")
	for _, m := range []string{"pam_login_custom_module.so", "pam_logout_custom_module.so",
		"pam_ssh_auth_module.so", "libnss_vaultaire.so.2"} {
		p.ecrire("opt/vaultaire/vaultaire_client/"+famille+"/"+m, famille)
	}
	for _, f := range []string{"opt/vaultaire/vaultaire_client/vaultaire_client", "opt/vaultaire/client_software.yaml",
		"opt/vaultaire/privatekey.pem", "opt/vaultaire/core_key_fingerprint"} {
		p.ecrire(f, "x")
	}
	p.ecrire("opt/vaultaire/client_conf.json", `{"servers":[{"ip":"10.0.0.1","port":6666}]}`)
	return p
}

// installer joue le script de la famille, à blanc.
func (p poste) installer() {
	p.t.Helper()
	cmd := exec.Command("bash", dossierScripts+p.famille+".sh")
	cmd.Env = append(os.Environ(), "VAULTAIRE_RACINE="+p.racine, "VAULTAIRE_LDD=true")
	if sortie, err := cmd.CombinedOutput(); err != nil {
		p.t.Fatalf("%s.sh : %v\n%s", p.famille, err, sortie)
	}
}

// tenus : les fichiers que la réconciliation tient sur ce poste.
func (p poste) tenus() []string {
	l := []string{"etc/pam.d/login", "etc/pam.d/sshd", "etc/ssh/sshd_config", "etc/nsswitch.conf"}
	if _, ok := p.origine["etc/pam.d/gdm-password"]; ok {
		l = append(l, "etc/pam.d/gdm-password", "etc/dconf/db/gdm.d/10-vaultaire-userlist")
	}
	return l
}

// fauxSysteme : enregistre, et répond par reponses.
type fauxSysteme struct {
	mu       sync.Mutex
	appels   []string
	reponses func(nom string, args []string) ([]byte, error)
}

func (f *fauxSysteme) Systeme(nom string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.appels = append(f.appels, nom+" "+strings.Join(args, " "))
	f.mu.Unlock()
	if f.reponses != nil {
		return f.reponses(nom, args)
	}
	if nom == "sshd" && len(args) > 0 && args[0] == "-T" {
		return []byte(sortieSSHDTConforme), nil
	}
	return nil, nil
}

// ecritures : les appels hors lecture — « sshd -T » ne change rien.
func (f *fauxSysteme) ecritures() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.appels {
		if !strings.HasPrefix(a, "sshd -T ") {
			out = append(out, a)
		}
	}
	return out
}

// sortieSSHDTConforme : un extrait de « sshd -T » sur une machine en règle —
// clés en minuscules, comme OpenSSH les imprime.
const sortieSSHDTConforme = `port 22
usepam yes
pubkeyauthentication yes
kbdinteractiveauthentication yes
passwordauthentication no
authenticationmethods publickey,keyboard-interactive
authorizedkeyscommand /usr/bin/vaultaire_client --fetch-key %u
authorizedkeyscommanduser root
subsystem sftp /usr/libexec/openssh/sftp-server
`

func (f *fauxSysteme) a(prefixe string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.appels {
		if strings.HasPrefix(a, prefixe) {
			return true
		}
	}
	return false
}

var instant = time.Date(2026, 10, 18, 12, 15, 30, 0, time.UTC)

func (p poste) env(f *fauxSysteme) Env {
	return Env{Racine: p.racine, Famille: p.famille, Systeme: f.Systeme,
		Horloge: func() time.Time { return instant }, DossierSauvegardes: p.chemin("var/lib/vaultaire/confsys/sauvegardes")}
}

// sshdRefuse : un faux sshd qui refuse tout candidat.
func sshdRefuse(nom string, _ []string) ([]byte, error) {
	if nom == "sshd" {
		return []byte("/etc/ssh/sshd_config line 9: Directive 'UsePAM' is not allowed within a Match block\n"),
			errors.New("exit status 255")
	}
	return nil, nil
}

// sansMarqueurs : ce qu'écrivait un script d'avant le 117 — les mêmes
// fichiers, sans leurs marqueurs.
func sansMarqueurs(c string) string {
	var out []string
	for _, l := range lignes(c) {
		if !strings.HasPrefix(l, PrefixeMarqueur) {
			out = append(out, l)
		}
	}
	return joindre(out)
}
