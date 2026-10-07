package controle

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// debian.sh — l'installation sur Debian et Ubuntu (TO-DO 71).
//
// Ce script n'écrit pas les piles PAM : il s'insère dans celles de la
// distribution. La sentinelle de rocky.sh, qui lit des piles écrites en clair,
// ne peut donc pas le garder. Ces tests le JOUENT, à blanc
// (VAULTAIRE_RACINE), sur une arborescence qui a la forme d'un Debian, et
// lisent ce qu'il en a fait.

const scriptDebian = "../../../automatisation/auto_deployements/debian.sh"

const pileLoginDebian = `#
# The PAM configuration file for the Shadow 'login' service
#
auth       optional   pam_faildelay.so  delay=3000000
auth       requisite  pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session    required     pam_loginuid.so
session       required   pam_env.so readenv=1

# Standard Un*x authentication.
@include common-auth

auth       optional   pam_group.so
session    required   pam_limits.so
@include common-account
@include common-session
@include common-password
`

const pileSSHDebian = `# PAM configuration for the Secure Shell service

# Standard Un*x authentication.
@include common-auth

account    required     pam_nologin.so
@include common-account
session    required     pam_loginuid.so
@include common-session
session    required     pam_limits.so
@include common-password
`

const pileGDMDebian = `#%PAM-1.0
auth    requisite       pam_nologin.so
auth    required        pam_succeed_if.so user != root quiet_success
@include common-auth
auth    optional        pam_gnome_keyring.so
@include common-account
session required        pam_loginuid.so
@include common-session
session optional        pam_gnome_keyring.so auto_start
@include common-password
`

const sshdConfigDebian = `Include /etc/ssh/sshd_config.d/*.conf

#PubkeyAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
Subsystem	sftp	/usr/lib/openssh/sftp-server
`

type posteDEssai struct {
	t      *testing.T
	racine string
	// multiarch : le répertoire où ce poste range ses bibliothèques.
	multiarch string
}

func (p posteDEssai) chemin(rel string) string { return filepath.Join(p.racine, rel) }

func (p posteDEssai) ecrire(rel, contenu string) {
	p.t.Helper()
	if err := os.MkdirAll(filepath.Dir(p.chemin(rel)), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(p.chemin(rel), []byte(contenu), 0o644); err != nil {
		p.t.Fatal(err)
	}
}

func (p posteDEssai) lire(rel string) string {
	p.t.Helper()
	brut, err := os.ReadFile(p.chemin(rel))
	if err != nil {
		p.t.Fatalf("%s : %v", rel, err)
	}
	return string(brut)
}

func (p posteDEssai) existe(rel string) bool {
	_, err := os.Stat(p.chemin(rel))
	return err == nil
}

// nouveauPoste monte un poste Debian neuf, où openssh-server est installé.
func nouveauPoste(t *testing.T, multiarch string) posteDEssai {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("le script d'installation ne se joue que sous Linux")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash absent")
	}
	p := posteDEssai{t: t, racine: t.TempDir(), multiarch: multiarch}
	p.ecrire("lib/"+multiarch+"/security/pam_unix.so", "")
	p.ecrire("etc/pam.d/login", pileLoginDebian)
	p.ecrire("etc/pam.d/sshd", pileSSHDebian)
	p.ecrire("etc/pam.d/common-auth", "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n")
	p.ecrire("etc/nsswitch.conf", "passwd:         files systemd\ngroup:          files systemd\nshadow:         files\nhosts:          files dns\n")
	p.ecrire("etc/ssh/sshd_config", sshdConfigDebian)
	p.ecrire("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	return p
}

// deposer place ce que le core envoie avant de lancer le script.
func (p posteDEssai) deposer(sans ...string) {
	p.t.Helper()
	absent := map[string]bool{}
	for _, s := range sans {
		absent[s] = true
	}
	for _, f := range []string{
		"opt/vaultaire/vaultaire_client/pam_login_custom_module.so",
		"opt/vaultaire/vaultaire_client/pam_logout_custom_module.so",
		"opt/vaultaire/vaultaire_client/pam_ssh_auth_module.so",
		"opt/vaultaire/vaultaire_client/libnss_vaultaire.so.2",
		"opt/vaultaire/vaultaire_client/vaultaire_client",
		"opt/vaultaire/client_software.yaml",
		"opt/vaultaire/privatekey.pem",
		"opt/vaultaire/core_key_fingerprint",
	} {
		if !absent[filepath.Base(f)] {
			p.ecrire(f, "x")
		}
	}
	p.ecrire("opt/vaultaire/client_conf.json", `{"servers":[{"ip":"10.0.0.1","port":6666}]}`)
}

// installer joue debian.sh à blanc sur ce poste.
func (p posteDEssai) installer(env ...string) (string, error) {
	p.t.Helper()
	cmd := exec.Command("bash", scriptDebian)
	cmd.Env = append(os.Environ(), "VAULTAIRE_RACINE="+p.racine, "VAULTAIRE_LDD=true")
	cmd.Env = append(cmd.Env, env...)
	sortie, err := cmd.CombinedOutput()
	return string(sortie), err
}

func lignesVaultaire(pile string) []string {
	var out []string
	for _, l := range strings.Split(pile, "\n") {
		if strings.HasSuffix(strings.TrimSpace(l), "# vaultaire") {
			out = append(out, l)
		}
	}
	return out
}

// ligneApres rend la ligne qui suit immédiatement celle qui commence ainsi.
func ligneApres(pile, debut string) string {
	lignes := strings.Split(pile, "\n")
	for i, l := range lignes {
		if strings.HasPrefix(strings.TrimSpace(l), debut) && i+1 < len(lignes) {
			return strings.TrimSpace(lignes[i+1])
		}
	}
	return ""
}

var controleAttendu = regexp.MustCompile(`^auth\s+\[success=done ignore=ignore default=(die|bad)\]\s+pam_(login_custom|ssh_auth)_module\.so\s+# vaultaire$`)

func TestDebianBrancheLesPilesSansLesReecrire(t *testing.T) {
	p := nouveauPoste(t, "x86_64-linux-gnu")
	p.deposer()
	if sortie, err := p.installer(); err != nil {
		t.Fatalf("installation : %v\n%s", err, sortie)
	}

	for pile, module := range map[string]string{"login": "pam_login_custom_module.so", "sshd": "pam_ssh_auth_module.so"} {
		contenu := p.lire("etc/pam.d/" + pile)
		var auth []string
		for _, l := range lignesVaultaire(contenu) {
			if strings.HasPrefix(l, "auth") {
				auth = append(auth, l)
			}
		}
		if len(auth) != 1 || !controleAttendu.MatchString(auth[0]) || !strings.Contains(auth[0], module) {
			t.Errorf("pile %s : ligne d'authentification posée = %q", pile, auth)
			continue
		}
		// La porte de secours : la ligne qui SUIT est l'authentification
		// locale de la distribution. Un compte local, pour qui le module
		// s'efface, y arrive.
		if suit := ligneApres(contenu, "auth    [success=done"); suit != "@include common-auth" {
			t.Errorf("pile %s : la ligne qui suit le module est %q, attendu « @include common-auth »", pile, suit)
		}
		// Le reste de la pile est celui de la distribution, ligne pour ligne.
		original := map[string]string{"login": pileLoginDebian, "sshd": pileSSHDebian}[pile]
		var sansNous []string
		for _, l := range strings.Split(contenu, "\n") {
			if !strings.HasSuffix(strings.TrimSpace(l), "# vaultaire") {
				sansNous = append(sansNous, l)
			}
		}
		if strings.Join(sansNous, "\n") != original {
			t.Errorf("pile %s : le script a changé autre chose que ses propres lignes", pile)
		}
		if p.lire("etc/pam.d/"+pile+".avant-vaultaire") != original {
			t.Errorf("pile %s : l'original n'est pas gardé sous .avant-vaultaire", pile)
		}
	}

	// Avant « @include common-auth », pas avant pam_nologin : un compte de
	// l'annuaire reste soumis à /etc/nologin.
	login := p.lire("etc/pam.d/login")
	if strings.Index(login, "pam_login_custom_module.so") < strings.Index(login, "pam_nologin.so") {
		t.Error("pile login : le module est posé avant pam_nologin")
	}
	if !strings.Contains(login, "session required    pam_logout_custom_module.so  # vaultaire") {
		t.Error("pile login : la ligne de fin de session manque")
	}
	if strings.Contains(p.lire("etc/pam.d/sshd"), "pam_logout_custom_module") {
		t.Error("pile sshd : une ligne de session a été posée — rocky.sh n'en pose pas pour sshd")
	}
}

func TestDebianPoseLesModulesLaOuPAMLesCherche(t *testing.T) {
	for _, multiarch := range []string{"x86_64-linux-gnu", "aarch64-linux-gnu"} {
		p := nouveauPoste(t, multiarch)
		p.deposer()
		if sortie, err := p.installer(); err != nil {
			t.Fatalf("%s : %v\n%s", multiarch, err, sortie)
		}
		for _, f := range []string{
			"lib/" + multiarch + "/security/pam_login_custom_module.so",
			"lib/" + multiarch + "/security/pam_logout_custom_module.so",
			"lib/" + multiarch + "/security/pam_ssh_auth_module.so",
			"lib/" + multiarch + "/libnss_vaultaire.so.2",
			"usr/bin/vaultaire_client",
			"etc/vaultaire_client/client_conf.json",
			"etc/vaultaire_client/.ssh/core_key_fingerprint",
			"etc/vaultaire_client/.ssh/privatekey.pem",
		} {
			if !p.existe(f) {
				t.Errorf("%s : %s manque après l'installation", multiarch, f)
			}
		}
		if p.existe("opt/vaultaire") {
			t.Errorf("%s : les sources d'installation n'ont pas été retirées", multiarch)
		}
	}
}

func TestDebianConfigureNSSEtSSH(t *testing.T) {
	p := nouveauPoste(t, "x86_64-linux-gnu")
	p.deposer()
	if sortie, err := p.installer(); err != nil {
		t.Fatalf("installation : %v\n%s", err, sortie)
	}
	nss := p.lire("etc/nsswitch.conf")
	for _, base := range []string{"passwd:         files systemd vaultaire", "group:          files systemd vaultaire"} {
		if !strings.Contains(nss, base) {
			t.Errorf("nsswitch.conf : %q manque\n%s", base, nss)
		}
	}
	if strings.Contains(nss, "shadow:         files vaultaire") || strings.Contains(nss, "dns vaultaire") {
		t.Errorf("nsswitch.conf : une autre base que passwd et group a été modifiée\n%s", nss)
	}

	sshd := p.lire("etc/ssh/sshd_config")
	for _, voulu := range []string{
		"UsePAM yes", "KbdInteractiveAuthentication yes",
		"AuthenticationMethods publickey,keyboard-interactive",
		"AuthorizedKeysCommand /usr/bin/vaultaire_client --fetch-key %u",
		"X11Forwarding yes",
	} {
		if !strings.Contains(sshd, voulu+"\n") {
			t.Errorf("sshd_config : %q manque", voulu)
		}
	}
	if strings.Contains(sshd, "KbdInteractiveAuthentication no") {
		t.Error("sshd_config : l'ancienne directive est restée, et la première lue l'emporte")
	}
	if strings.Count(sshd, "Include /etc/ssh/sshd_config.d/*.conf") != 1 ||
		strings.Index(sshd, "Include") < strings.Index(sshd, "AuthenticationMethods") {
		t.Error("sshd_config : l'inclusion doit venir après nos directives, une seule fois")
	}
	if p.lire("etc/ssh/sshd_config.avant-vaultaire") != sshdConfigDebian {
		t.Error("sshd_config : l'original n'est pas gardé")
	}
	if !strings.Contains(p.lire("etc/ssh/sshd_config.d/50-cloud-init.conf"), "#PasswordAuthentication yes disabled_by_vaultaire") {
		t.Error("sshd_config.d : PasswordAuthentication n'est pas neutralisé")
	}
}

// Rejouer le script — une réinstallation, une mise à jour — ne double rien.
func TestDebianSeRejoueSansRienDoubler(t *testing.T) {
	p := nouveauPoste(t, "x86_64-linux-gnu")
	etat := func() string {
		return p.lire("etc/pam.d/login") + p.lire("etc/pam.d/sshd") + p.lire("etc/nsswitch.conf") + p.lire("etc/ssh/sshd_config")
	}
	p.deposer()
	if sortie, err := p.installer(); err != nil {
		t.Fatalf("première installation : %v\n%s", err, sortie)
	}
	premier := etat()
	for i := 0; i < 2; i++ {
		p.deposer()
		if sortie, err := p.installer(); err != nil {
			t.Fatalf("réinstallation %d : %v\n%s", i+1, err, sortie)
		}
	}
	if etat() != premier {
		t.Errorf("le script rejoué ne laisse pas la machine dans le même état :\n%s", etat())
	}
	// L'original gardé reste celui d'AVANT Vaultaire, pas la pile déjà branchée.
	if p.lire("etc/pam.d/sshd.avant-vaultaire") != pileSSHDebian {
		t.Error("la copie de l'original a été écrasée par une pile déjà branchée")
	}
	if p.lire("etc/ssh/sshd_config.avant-vaultaire") != sshdConfigDebian {
		t.Error("la copie de sshd_config d'origine a été écrasée par celle que le script a produite")
	}
}

func TestDebianBrancheGDMQuandIlEstLa(t *testing.T) {
	p := nouveauPoste(t, "x86_64-linux-gnu")
	p.ecrire("etc/pam.d/gdm-password", pileGDMDebian)
	p.deposer()
	if sortie, err := p.installer(); err != nil {
		t.Fatalf("installation : %v\n%s", err, sortie)
	}
	gdm := p.lire("etc/pam.d/gdm-password")
	if !strings.Contains(gdm, "auth    [success=done ignore=ignore default=bad]    pam_login_custom_module.so  # vaultaire\n@include common-auth") {
		t.Errorf("pile gdm-password mal branchée :\n%s", gdm)
	}
	if !strings.Contains(gdm, "pam_logout_custom_module.so  # vaultaire") {
		t.Error("pile gdm-password : la ligne de fin de session manque")
	}
	if !strings.Contains(p.lire("etc/dconf/db/gdm.d/10-vaultaire-userlist"), "disable-user-list=true") {
		t.Error("la liste des comptes de l'écran de connexion n'est pas masquée")
	}
}

// rienNAEteTouche vérifie que NSS, SSH et PAM sont comme à l'arrivée.
func (p posteDEssai) rienNAEteTouche(quand string) {
	p.t.Helper()
	for rel, original := range map[string]string{
		"etc/pam.d/login":     pileLoginDebian,
		"etc/pam.d/sshd":      pileSSHDebian,
		"etc/ssh/sshd_config": sshdConfigDebian,
	} {
		if p.lire(rel) != original {
			p.t.Errorf("%s : %s a été modifié", quand, rel)
		}
	}
	if strings.Contains(p.lire("etc/nsswitch.conf"), "vaultaire") {
		p.t.Errorf("%s : nsswitch.conf a été modifié", quand)
	}
	restes, _ := filepath.Glob(p.chemin("etc/pam.d/*.vaultaire-nouveau"))
	if len(restes) > 0 {
		p.t.Errorf("%s : des piles préparées traînent : %v", quand, restes)
	}
}

// LE garde-fou propre à ce script. Un module qui ne se charge pas, derrière
// « default=die », refuse TOUT le monde — root et les comptes locaux compris.
// Le script doit s'arrêter avant d'avoir branché quoi que ce soit.
func TestDebianSArreteAvantPAMSiUnModuleNeSeChargePas(t *testing.T) {
	p := nouveauPoste(t, "x86_64-linux-gnu")
	p.deposer()
	fauxLdd := filepath.Join(t.TempDir(), "ldd")
	if err := os.WriteFile(fauxLdd, []byte("#!/bin/sh\necho \"	libc.so.6 => /lib/libc.so.6 (0x0)\"\n"+
		"echo \"$1: /lib/libc.so.6: version \\`GLIBC_2.38' not found (required by $1)\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sortie, err := p.installer("VAULTAIRE_LDD=" + fauxLdd)
	if err == nil {
		t.Fatalf("le script a continué avec des modules qui ne se chargent pas :\n%s", sortie)
	}
	if !strings.Contains(sortie, "ne se charge pas") || !strings.Contains(sortie, "AVANT la configuration de NSS, SSH et PAM") {
		t.Errorf("le motif de l'arrêt n'est pas dit :\n%s", sortie)
	}
	p.rienNAEteTouche("module qui ne se charge pas")
}

func TestDebianSArreteSiUnModuleManque(t *testing.T) {
	p := nouveauPoste(t, "x86_64-linux-gnu")
	p.deposer("pam_ssh_auth_module.so")
	sortie, err := p.installer()
	if err == nil {
		t.Fatalf("le script a continué sans le module SSH :\n%s", sortie)
	}
	if !strings.Contains(sortie, "Modules natifs incomplets") {
		t.Errorf("le motif de l'arrêt n'est pas dit :\n%s", sortie)
	}
	p.rienNAEteTouche("module manquant")
}

// Une pile que quelqu'un a réécrite : le script ne devine pas, et ne branche
// AUCUNE pile — pas même celles qu'il savait brancher.
func TestDebianNeDevinePasUnePilePersonnalisee(t *testing.T) {
	p := nouveauPoste(t, "x86_64-linux-gnu")
	personnalisee := "auth required pam_sss.so\naccount required pam_unix.so\nsession required pam_unix.so\n"
	p.ecrire("etc/pam.d/sshd", personnalisee)
	p.deposer()
	sortie, err := p.installer()
	if err == nil {
		t.Fatalf("le script a branché une pile sans « @include common-auth » :\n%s", sortie)
	}
	if !strings.Contains(sortie, "aucune pile PAM n'a été modifiée") || !strings.Contains(sortie, "pam_ssh_auth_module.so") {
		t.Errorf("le script ne dit pas quoi faire à la main :\n%s", sortie)
	}
	if p.lire("etc/pam.d/sshd") != personnalisee || p.lire("etc/pam.d/login") != pileLoginDebian {
		t.Error("une pile a été modifiée alors que le script s'est arrêté")
	}
	if restes, _ := filepath.Glob(p.chemin("etc/pam.d/*.vaultaire-nouveau")); len(restes) > 0 {
		t.Errorf("des piles préparées traînent : %v", restes)
	}
}

func TestDebianSansSSHInstalleSArrete(t *testing.T) {
	p := nouveauPoste(t, "x86_64-linux-gnu")
	if err := os.Remove(p.chemin("etc/pam.d/sshd")); err != nil {
		t.Fatal(err)
	}
	p.deposer()
	sortie, err := p.installer()
	if err == nil || !strings.Contains(sortie, "openssh-server") {
		t.Fatalf("attendu un arrêt qui nomme openssh-server (err=%v) :\n%s", err, sortie)
	}
	if p.lire("etc/pam.d/login") != pileLoginDebian {
		t.Error("la pile login a été modifiée alors que le script s'est arrêté")
	}
}

// L'ordre, lu dans le texte : ce que les essais à blanc ne peuvent pas voir,
// puisque le contrôle de l'agent n'y est pas joué.
func TestDebianControleLAgentPuisLesModulesAvantPAM(t *testing.T) {
	script := lire(t, scriptDebian)
	rang := func(repere string) int {
		k := strings.Index(script, repere)
		if k < 0 {
			t.Fatalf("repère %q introuvable dans debian.sh", repere)
		}
		return k
	}
	modules := rang(`log_info "Vérification du chargement des modules natifs..."`)
	agent := rang("systeme /usr/bin/vaultaire_client --install-unit")
	nss := rang(`log_info "Configuration de NSS..."`)
	ssh := rang(`log_info "Configuration sécurisée de SSHD..."`)
	pose := rang(`log_info "Mise en place des piles PAM..."`)
	if !(modules < nss && modules < ssh && modules < pose) {
		t.Error("les modules sont éprouvés après une modification de NSS, SSH ou PAM")
	}
	if !(agent < nss && agent < ssh && agent < pose) {
		t.Error("l'agent est contrôlé après une modification de NSS, SSH ou PAM")
	}
	if !(nss < pose && ssh < pose) {
		t.Error("les piles PAM sont posées avant la fin des étapes qui peuvent échouer")
	}
	if strings.Contains(script, "cat > /etc/pam.d/") || strings.Contains(script, `cat > "$R/etc/pam.d/`) {
		t.Error("debian.sh réécrit une pile PAM entière : il doit s'insérer dans celle de la distribution")
	}
	if strings.Contains(script, "cat > /etc/systemd/system/vaultaire_client.service") {
		t.Error("debian.sh écrit l'unité lui-même : c'est « vaultaire_client --install-unit » qui l'écrit")
	}
	// Le raccourci d'essai ne doit pas pouvoir servir sur une vraie machine.
	if !strings.Contains(script, `if essai; then LDD="${VAULTAIRE_LDD:-ldd}"; else LDD=ldd; fi`) {
		t.Error("VAULTAIRE_LDD doit rester sans effet hors d'un essai à blanc")
	}
}
