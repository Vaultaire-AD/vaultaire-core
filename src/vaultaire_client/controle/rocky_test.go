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

// rocky.sh — les précautions de debian.sh (TO-DO 174) et les modules par
// famille (TO-DO 173), joués à blanc (VAULTAIRE_RACINE) sur une arborescence
// qui a la forme d'une Rocky 9.

const scriptRocky = "../../../automatisation/auto_deployements/rocky.sh"

const pileLoginRocky = `#%PAM-1.0
auth       substack     system-auth
auth       include      postlogin
account    required     pam_nologin.so
account    include      system-auth
password   include      system-auth
session    include      system-auth
session    include      postlogin
`

// Une pile sshd retouchée par un administrateur : c'est elle que la copie doit
// garder.
const pileSSHRocky = `#%PAM-1.0
auth       required     pam_faillock.so preauth # ajouté par l'équipe sécurité
auth       substack     password-auth
auth       include      postlogin
account    required     pam_nologin.so
account    include      password-auth
session    include      password-auth
`

const sshdConfigRocky = `Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin prohibit-password
UsePAM yes
Subsystem	sftp	/usr/libexec/openssh/sftp-server
`

const nsswitchRocky = "passwd:     sss files systemd\ngroup:      sss files systemd\nshadow:     files\nhosts:      files dns myhostname\n"

// nouveauPosteRocky monte une Rocky 9 neuve, où openssh-server est installé.
func nouveauPosteRocky(t *testing.T) posteDEssai {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("le script d'installation ne se joue que sous Linux")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash absent")
	}
	p := posteDEssai{t: t, racine: t.TempDir()}
	p.ecrire("usr/lib64/security/pam_unix.so", "")
	p.ecrire("etc/pam.d/login", pileLoginRocky)
	p.ecrire("etc/pam.d/sshd", pileSSHRocky)
	p.ecrire("etc/nsswitch.conf", nsswitchRocky)
	p.ecrire("etc/ssh/sshd_config", sshdConfigRocky)
	p.ecrire("etc/ssh/sshd_config.d/50-redhat.conf", "PasswordAuthentication yes\n")
	return p
}

var modulesNatifs = []string{
	"pam_login_custom_module.so",
	"pam_logout_custom_module.so",
	"pam_ssh_auth_module.so",
	"libnss_vaultaire.so.2",
}

// deposerModules range les quatre modules natifs dans un répertoire de ce que
// le core envoie ("" pour la racine, « rocky » ou « debian » pour une
// famille). Chaque fichier contient le nom de son répertoire : on lit ensuite
// lequel a été posé.
func (p posteDEssai) deposerModules(famille string) {
	p.t.Helper()
	marque := famille
	if marque == "" {
		marque = "racine"
	}
	for _, m := range modulesNatifs {
		p.ecrire(filepath.Join("opt/vaultaire/vaultaire_client", famille, m), marque)
	}
}

// deposerReste place ce que le core envoie hors des modules natifs.
func (p posteDEssai) deposerReste() {
	p.t.Helper()
	for _, f := range []string{
		"opt/vaultaire/vaultaire_client/vaultaire_client",
		"opt/vaultaire/client_software.yaml",
		"opt/vaultaire/privatekey.pem",
		"opt/vaultaire/core_key_fingerprint",
	} {
		p.ecrire(f, "x")
	}
	p.ecrire("opt/vaultaire/client_conf.json", `{"servers":[{"ip":"10.0.0.1","port":6666}]}`)
}

func (p posteDEssai) installerRocky(env ...string) (string, error) {
	p.t.Helper()
	cmd := exec.Command("bash", scriptRocky)
	cmd.Env = append(os.Environ(), "VAULTAIRE_RACINE="+p.racine, "VAULTAIRE_LDD=true")
	cmd.Env = append(cmd.Env, env...)
	sortie, err := cmd.CombinedOutput()
	return string(sortie), err
}

func (p posteDEssai) rienNAEteToucheRocky(quand string) {
	p.t.Helper()
	for rel, original := range map[string]string{
		"etc/pam.d/login":     pileLoginRocky,
		"etc/pam.d/sshd":      pileSSHRocky,
		"etc/ssh/sshd_config": sshdConfigRocky,
		"etc/nsswitch.conf":   nsswitchRocky,
	} {
		if p.lire(rel) != original {
			p.t.Errorf("%s : %s a été modifié", quand, rel)
		}
	}
	restes, _ := filepath.Glob(p.chemin("etc/pam.d/*.vaultaire-nouveau"))
	if len(restes) > 0 {
		p.t.Errorf("%s : des piles préparées traînent : %v", quand, restes)
	}
	if avant, _ := filepath.Glob(p.chemin("etc/pam.d/*.avant-vaultaire")); len(avant) > 0 {
		p.t.Errorf("%s : des copies d'origine ont été faites alors que rien n'a été posé : %v", quand, avant)
	}
}

// TO-DO 173 : sur une Rocky, ce sont les modules compilés sur Rocky 9 qui sont
// posés — pas ceux de la famille Debian, pas ceux de la racine.
func TestRockyPoseLesModulesDeSaFamille(t *testing.T) {
	p := nouveauPosteRocky(t)
	p.deposerModules("rocky")
	p.deposerModules("debian")
	p.deposerModules("")
	p.deposerReste()
	sortie, err := p.installerRocky()
	if err != nil {
		t.Fatalf("installation : %v\n%s", err, sortie)
	}
	for _, f := range []string{
		"usr/lib64/security/pam_login_custom_module.so",
		"usr/lib64/security/pam_logout_custom_module.so",
		"usr/lib64/security/pam_ssh_auth_module.so",
		"usr/lib64/libnss_vaultaire.so.2",
	} {
		if got := p.lire(f); got != "rocky" {
			t.Errorf("%s : posé depuis « %s », attendu la famille rocky", f, got)
		}
	}
	for _, f := range []string{"usr/bin/vaultaire_client", "etc/vaultaire_client/client_conf.json",
		"etc/vaultaire_client/.ssh/core_key_fingerprint", "etc/vaultaire_client/.ssh/privatekey.pem"} {
		if !p.existe(f) {
			t.Errorf("%s manque après l'installation", f)
		}
	}
	if p.existe("opt/vaultaire") {
		t.Error("les sources d'installation n'ont pas été retirées")
	}
	if strings.Contains(sortie, "non classés") {
		t.Errorf("l'avertissement des modules non classés est donné alors que la famille est là :\n%s", sortie)
	}
}

// Un core compilé sur un poste de développement n'envoie que des modules non
// classés : ils sont pris, en le disant.
func TestRockyPrendLesModulesNonClassesSiSaFamilleManque(t *testing.T) {
	p := nouveauPosteRocky(t)
	p.deposerModules("")
	p.deposerModules("debian")
	p.deposerReste()
	sortie, err := p.installerRocky()
	if err != nil {
		t.Fatalf("installation : %v\n%s", err, sortie)
	}
	if got := p.lire("usr/lib64/security/pam_ssh_auth_module.so"); got != "racine" {
		t.Errorf("module posé depuis « %s », attendu la racine — jamais la famille Debian", got)
	}
	if !strings.Contains(sortie, "non classés par famille") {
		t.Errorf("le repli sur des modules non classés n'est pas dit :\n%s", sortie)
	}
}

// La même règle, côté Debian.
func TestDebianPrendLesModulesDeSaFamille(t *testing.T) {
	p := nouveauPoste(t, "x86_64-linux-gnu")
	p.deposer() // racine, comme avant le TO-DO 173
	for _, m := range modulesNatifs {
		p.ecrire("opt/vaultaire/vaultaire_client/debian/"+m, "debian")
		p.ecrire("opt/vaultaire/vaultaire_client/rocky/"+m, "rocky")
	}
	if sortie, err := p.installer(); err != nil {
		t.Fatalf("installation : %v\n%s", err, sortie)
	}
	if got := p.lire("lib/x86_64-linux-gnu/security/pam_login_custom_module.so"); got != "debian" {
		t.Errorf("module posé depuis « %s », attendu la famille debian", got)
	}
	if got := p.lire("lib/x86_64-linux-gnu/libnss_vaultaire.so.2"); got != "debian" {
		t.Errorf("bibliothèque NSS posée depuis « %s », attendu la famille debian", got)
	}
}

// TO-DO 174 : LE garde-fou. Un module qui ne se charge pas, derrière
// « default=die », refuse tout le monde. Le script s'arrête avant d'avoir
// touché à NSS, SSH ou PAM.
func TestRockySArreteAvantPAMSiUnModuleNeSeChargePas(t *testing.T) {
	p := nouveauPosteRocky(t)
	p.deposerModules("rocky")
	p.deposerReste()
	fauxLdd := filepath.Join(t.TempDir(), "ldd")
	if err := os.WriteFile(fauxLdd, []byte("#!/bin/sh\necho \"	libc.so.6 => /lib64/libc.so.6 (0x0)\"\n"+
		"echo \"$1: /lib64/libc.so.6: version \\`GLIBC_2.38' not found (required by $1)\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sortie, err := p.installerRocky("VAULTAIRE_LDD=" + fauxLdd)
	if err == nil {
		t.Fatalf("le script a continué avec des modules qui ne se chargent pas :\n%s", sortie)
	}
	if !strings.Contains(sortie, "ne se charge pas") || !strings.Contains(sortie, "AVANT la configuration de NSS, SSH et PAM") {
		t.Errorf("le motif de l'arrêt n'est pas dit :\n%s", sortie)
	}
	p.rienNAEteToucheRocky("module qui ne se charge pas")
}

func TestRockySArreteSiUnModuleManque(t *testing.T) {
	p := nouveauPosteRocky(t)
	p.deposerModules("rocky")
	if err := os.Remove(p.chemin("opt/vaultaire/vaultaire_client/rocky/libnss_vaultaire.so.2")); err != nil {
		t.Fatal(err)
	}
	p.deposerReste()
	sortie, err := p.installerRocky()
	if err == nil || !strings.Contains(sortie, "Modules natifs incomplets") {
		t.Fatalf("attendu un arrêt « Modules natifs incomplets » (err=%v) :\n%s", err, sortie)
	}
	p.rienNAEteToucheRocky("module manquant")
}

// libxcrypt-compat n'est plus installé d'office : seulement si ldd dit qu'il
// manque, et c'est alors lui — pas un autre — qui est demandé à dnf.
func TestRockyNInstalleQueCeQuiManque(t *testing.T) {
	p := nouveauPosteRocky(t)
	p.deposerModules("rocky")
	p.deposerReste()
	sortie, err := p.installerRocky()
	if err != nil {
		t.Fatalf("installation : %v\n%s", err, sortie)
	}
	if strings.Contains(sortie, "dnf") {
		t.Errorf("dnf est appelé alors que rien ne manque :\n%s", sortie)
	}

	// Des modules non classés qui demandent libcrypt.so.1 : le faux ldd la dit
	// absente au premier passage (quatre fichiers), présente ensuite — comme
	// après l'installation du paquet.
	p = nouveauPosteRocky(t)
	p.deposerModules("")
	p.deposerReste()
	compteur := filepath.Join(t.TempDir(), "n")
	fauxLdd := filepath.Join(t.TempDir(), "ldd")
	script := "#!/bin/sh\nn=$(cat " + compteur + " 2>/dev/null || echo 0); n=$((n+1)); echo $n > " + compteur + "\n" +
		"if [ $n -le 4 ]; then echo \"	libcrypt.so.1 => not found\"; fi\n"
	if err := os.WriteFile(fauxLdd, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	sortie, err = p.installerRocky("VAULTAIRE_LDD=" + fauxLdd)
	if err != nil {
		t.Fatalf("installation : %v\n%s", err, sortie)
	}
	if !strings.Contains(sortie, "[essai] dnf install -y -q libxcrypt-compat") {
		t.Errorf("la bibliothèque manquante n'est pas demandée à dnf :\n%s", sortie)
	}
}

// Les originaux sont gardés une fois — et rejouer le script ne les écrase pas
// par une pile déjà branchée, ni ne double rien.
func TestRockyGardeLesOriginauxEtSeRejoue(t *testing.T) {
	p := nouveauPosteRocky(t)
	gdm := "#%PAM-1.0\nauth substack password-auth\n"
	p.ecrire("etc/pam.d/gdm-password", gdm)
	etat := func() string {
		return p.lire("etc/pam.d/login") + p.lire("etc/pam.d/sshd") + p.lire("etc/pam.d/gdm-password") +
			p.lire("etc/nsswitch.conf") + p.lire("etc/ssh/sshd_config")
	}
	var premier string
	for i := 0; i < 3; i++ {
		p.deposerModules("rocky")
		p.deposerReste()
		if sortie, err := p.installerRocky(); err != nil {
			t.Fatalf("installation %d : %v\n%s", i+1, err, sortie)
		}
		if i == 0 {
			premier = etat()
		}
	}
	if etat() != premier {
		t.Errorf("le script rejoué ne laisse pas la machine dans le même état :\n%s", etat())
	}
	for rel, original := range map[string]string{
		"etc/pam.d/login":        pileLoginRocky,
		"etc/pam.d/sshd":         pileSSHRocky,
		"etc/pam.d/gdm-password": gdm,
		"etc/ssh/sshd_config":    sshdConfigRocky,
	} {
		if got := p.lire(rel + ".avant-vaultaire"); got != original {
			t.Errorf("%s.avant-vaultaire ne garde pas l'original d'avant Vaultaire :\n%s", rel, got)
		}
	}
	if !strings.Contains(p.lire("etc/pam.d/sshd"), "pam_ssh_auth_module.so") {
		t.Error("la pile sshd n'est pas branchée")
	}
	if restes, _ := filepath.Glob(p.chemin("etc/pam.d/*.vaultaire-nouveau")); len(restes) > 0 {
		t.Errorf("des piles préparées traînent : %v", restes)
	}
	nss := p.lire("etc/nsswitch.conf")
	if !strings.Contains(nss, "passwd:     sss files systemd vaultaire\n") || strings.Count(nss, "vaultaire") != 2 {
		t.Errorf("nsswitch.conf :\n%s", nss)
	}
	if !strings.Contains(p.lire("etc/ssh/sshd_config.d/50-redhat.conf"), "#PasswordAuthentication yes disabled_by_vaultaire") {
		t.Error("sshd_config.d : PasswordAuthentication n'est pas neutralisé")
	}
	if !strings.Contains(p.lire("etc/dconf/db/gdm.d/10-vaultaire-userlist"), "disable-user-list=true") {
		t.Error("la liste des comptes de l'écran de connexion n'est pas masquée")
	}
}

// L'ordre, lu dans le texte : ce que les essais à blanc ne peuvent pas voir.
func TestRockyEprouveLesModulesEtSSHAvantDePoserPAM(t *testing.T) {
	script := lire(t, scriptRocky)
	rang := func(repere string) int {
		t.Helper()
		k := strings.Index(script, repere)
		if k < 0 {
			t.Fatalf("repère %q introuvable dans rocky.sh", repere)
		}
		return k
	}
	modules := rang(`log_info "Vérification du chargement des modules natifs..."`)
	nss := rang(`log_info "Configuration de NSS..."`)
	ssh := rang(`log_info "Configuration sécurisée de SSHD..."`)
	validation := rang("if ! sshd -t")
	pose := rang(`log_info "Mise en place des piles PAM..."`)
	if !(modules < nss && modules < ssh && modules < pose) {
		t.Error("les modules sont éprouvés après une modification de NSS, SSH ou PAM")
	}
	if !(ssh < validation && validation < pose) {
		t.Error("sshd_config n'est pas validé entre sa réécriture et la pose des piles PAM")
	}
	for _, interdit := range []string{"cat > /etc/pam.d/", "chmod 644 /etc/pam.d/*", "dnf install -y -q libxcrypt-compat"} {
		if strings.Contains(script, interdit) {
			t.Errorf("rocky.sh contient encore « %s »", interdit)
		}
	}
	if !strings.Contains(script, `if essai; then LDD="${VAULTAIRE_LDD:-ldd}"; else LDD=ldd; fi`) {
		t.Error("VAULTAIRE_LDD doit rester sans effet hors d'un essai à blanc")
	}
	if !strings.Contains(script, `mv -f "${SSHD_CONF}.vaultaire-precedent" "$SSHD_CONF"`) {
		t.Error("une configuration refusée par sshd -t n'est plus remise comme elle était")
	}
}

// TO-DO 173 : une seule recette pour les modules natifs, sans libcurl.
func TestUneSeuleRecetteDesModulesNatifs(t *testing.T) {
	recette := lire(t, dossierDesModules+"auto_compil.sh")
	racine := lire(t, "../../../auto-compil.sh")
	horsCommentaire := regexp.MustCompile(`(?m)^[^#\n]*-lcurl`)
	if horsCommentaire.MatchString(recette) || horsCommentaire.MatchString(racine) {
		t.Error("les modules sont de nouveau liés à libcurl, qu'aucun n'appelle")
	}
	if regexp.MustCompile(`(?m)^\s*gcc\s`).MatchString(racine) {
		t.Error("auto-compil.sh compile lui-même : la recette est dans pam_module/auto_compil.sh, une seule fois")
	}
	if !strings.Contains(racine, "src/vaultaire_client/pam_module/auto_compil.sh") {
		t.Error("auto-compil.sh n'appelle plus la recette des modules natifs")
	}
	if !strings.Contains(recette, "VAULTAIRE_GLIBC_MAX") || !strings.Contains(recette, "objdump -T") {
		t.Error("la recette ne vérifie plus la version de glibc exigée")
	}
}
