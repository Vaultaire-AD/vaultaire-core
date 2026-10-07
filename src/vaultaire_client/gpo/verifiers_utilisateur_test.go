//go:build linux

package gpo

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TO-DO 163 — les modules utilisateur qui n'avaient pas de vérificateur, et les
// deux lectures qui passaient encore par un chemin.
//
// Comme pour le 135, tout part du VRAI appliqueur : la politique est appliquée
// dans un dossier personnel réel, l'état vient de BuildScopeState, le dossier
// est défait comme une personne le déferait, et le scan doit le voir. Aucune
// attente n'est écrite par un test.

func attenteDe(t *testing.T, etat *ScopeState, genre string) SystemCheck {
	t.Helper()
	for _, c := range etat.Checks {
		if c.Kind == genre {
			return c
		}
	}
	t.Fatalf("aucune attente %q dans l'etat (%d attente(s)) : le module n'est toujours pas verifie",
		genre, len(etat.Checks))
	return SystemCheck{}
}

func unSeulEcart(t *testing.T, constat DriftReport, genre DriftKind, fragment string) DriftItem {
	t.Helper()
	if len(constat.Items) != 1 {
		t.Fatalf("%d ecart(s), attendu un seul (%s, « %s ») : %+v", len(constat.Items), genre, fragment, constat.Items)
	}
	item := constat.Items[0]
	if item.Kind != genre || !strings.Contains(item.Detail, fragment) {
		t.Fatalf("ecart = %s « %s », attendu %s contenant « %s »", item.Kind, item.Detail, genre, fragment)
	}
	return item
}

// ---------------------------------------------------------------------------
// user_git_config
// ---------------------------------------------------------------------------

func git(t *testing.T, fichier string, args ...string) {
	t.Helper()
	complet := append([]string{"config", "--file", fichier}, args...)
	if sortie, err := exec.Command("git", complet...).CombinedOutput(); err != nil {
		t.Fatalf("git %v : %v (%s)", complet, err, sortie)
	}
}

func moduleGit(cle, valeur string) Module {
	return moduleU(ModuleUserGitConfig, "git-"+cle, map[string]string{"key": cle, "value": valeur})
}

func TestUneCleGitEstVerifiee(t *testing.T) {
	exigerCommande(t, "git")
	nom, home := compteDEssai(t)
	gitconfig := filepath.Join(home, ".gitconfig")
	politique := politiqueU(nom, moduleGit("user.email", "alice@acme.lan"))

	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	attente := attenteDe(t, etat, CheckGitConfig)
	if attente.Target != gitconfig+"#cle:user.email" || attente.StateKey != "git-user.email" {
		t.Fatalf("attente = %+v", attente)
	}
	if strings.Contains(attente.Expect, "alice") {
		t.Errorf("l'attente porte la valeur en clair (%q) : une valeur git peut contenir des virgules, "+
			"des signes egal — et l'attendu se decoupe dessus", attente.Expect)
	}
	// Avant le point 163 : zéro élément vérifié, donc « non vérifié » au core.
	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() || constat.Checked != 1 {
		t.Fatalf("juste apres l'application : %d verifie(s), %+v", constat.Checked, constat.Items)
	}

	// La personne règle AUTRE CHOSE dans son .gitconfig : c'est le sien.
	git(t, gitconfig, "core.editor", "vim")
	git(t, gitconfig, "alias.lg", "log --oneline, --graph = tout")
	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("regler une autre cle est signale comme un ecart : %+v", constat.Items)
	}

	// Elle change la clé de la politique.
	git(t, gitconfig, "user.email", "perso@exemple.org")
	constat := scanFromState(etat, ScopeUser, nom)
	unSeulEcart(t, constat, DriftSystemState, "cle git user.email modifiee")
	if modules := corriger(etat, constat); len(modules) != 1 || modules[0] != "git-user.email" {
		t.Fatalf("modules a rejouer = %v", modules)
	}
	etat2, rapport2 := appliquer(t, politique, etat)
	exigerApplique(t, rapport2)
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("apres reapplication : %+v", constat.Items)
	}
	// Et ce qu'elle avait réglé d'autre est toujours là.
	if brut, _ := os.ReadFile(gitconfig); !strings.Contains(string(brut), "editor = vim") {
		t.Errorf("la reapplication a emporte une cle de la personne :\n%s", brut)
	}

	// Elle la retire.
	git(t, gitconfig, "--unset", "user.email")
	unSeulEcart(t, scanFromState(etat2, ScopeUser, nom), DriftSystemState, "cle git user.email retiree")

	// Elle supprime le fichier.
	if err := os.Remove(gitconfig); err != nil {
		t.Fatal(err)
	}
	unSeulEcart(t, scanFromState(etat2, ScopeUser, nom), DriftSystemState, ".gitconfig supprime")
}

// Une valeur que l'attendu « a=1,b=2 » ne saurait pas porter, et une clé écrite
// avec une autre casse que celle sous laquelle git la rend.
func TestUneCleGitAuxCaracteresDifficilesEstVerifiee(t *testing.T) {
	exigerCommande(t, "git")
	nom, home := compteDEssai(t)
	valeur := "log --graph, --format=%h = %s ; tout"
	politique := politiqueU(nom, moduleGit("Alias.LG", valeur))

	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)
	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() || constat.Checked != 1 {
		t.Fatalf("%d verifie(s), %+v — la cle est ecrite « Alias.LG », git la rend « alias.lg »",
			constat.Checked, constat.Items)
	}
	// Une seule virgule de moins : si la valeur était découpée ou tronquée en
	// route, les deux se confondraient.
	git(t, filepath.Join(home, ".gitconfig"), "alias.lg", "log --graph --format=%h = %s ; tout")
	unSeulEcart(t, scanFromState(etat, ScopeUser, nom), DriftSystemState, "modifiee")
}

func TestUneCleGitRetireeQuiRevientEstVue(t *testing.T) {
	exigerCommande(t, "git")
	nom, home := compteDEssai(t)
	gitconfig := filepath.Join(home, ".gitconfig")
	git(t, gitconfig, "http.sslVerify", "false")
	if err := os.Chmod(gitconfig, 0o644); err != nil {
		t.Fatal(err)
	}
	retrait := moduleU(ModuleUserGitConfig, "git-ssl", map[string]string{"key": "http.sslVerify", "state": "absent"})

	etat, rapport := appliquer(t, politiqueU(nom, retrait), nil)
	exigerApplique(t, rapport)
	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() || constat.Checked != 1 {
		t.Fatalf("apres le retrait : %d verifie(s), %+v", constat.Checked, constat.Items)
	}
	git(t, gitconfig, "http.sslVerify", "false")
	unSeulEcart(t, scanFromState(etat, ScopeUser, nom), DriftSystemState, "retablie alors que la politique la retire")
}

// Un .gitconfig devenu lien n'est pas LU — la porte du point 162 reste fermée
// côté vérification — et c'est un constat : la politique avait écrit un fichier.
func TestUnGitconfigDevenuLienEstUnConstatEtNEstPasLu(t *testing.T) {
	exigerCommande(t, "git")
	nom, home := compteDEssai(t)
	etat, rapport := appliquer(t, politiqueU(nom, moduleGit("user.email", "alice@acme.lan")), nil)
	exigerApplique(t, rapport)

	ailleurs := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(ailleurs, []byte("[user]\n\temail = alice@acme.lan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitconfig := filepath.Join(home, ".gitconfig")
	if err := os.Remove(gitconfig); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ailleurs, gitconfig); err != nil {
		t.Fatal(err)
	}
	// Le fichier au bout du lien porte la bonne valeur : un vérificateur qui
	// suivrait le lien dirait « conforme ».
	unSeulEcart(t, scanFromState(etat, ScopeUser, nom), DriftSystemState, "n'est plus un fichier ordinaire du compte")
}

func TestLaFormeCanoniqueDUneCleGit(t *testing.T) {
	cas := map[string]string{
		"user.email":                   "user.email",
		"User.Email":                   "user.email",
		"core.autoCRLF":                "core.autocrlf",
		"url.HTTPS://Git.x/.insteadOf": "url.HTTPS://Git.x/.insteadof",
		"Remote.Origin.URL":            "remote.Origin.url",
		"sansPoint":                    "sanspoint",
	}
	for cle, veut := range cas {
		if got := cleGitCanonique(cle); got != veut {
			t.Errorf("%q → %q, attendu %q", cle, got, veut)
		}
	}
}

// ---------------------------------------------------------------------------
// user_password_policy
// ---------------------------------------------------------------------------

// fauxChage tient lieu de `chage` : il retient ce que l'appliqueur règle, et
// rend ce que `chage -l` en dirait. Le vrai exige un compte et le modifie.
type fauxChage struct {
	max, warn string
	appels    [][]string
}

func (f *fauxChage) installer(t *testing.T) {
	t.Helper()
	ancienne, ancienneLecture, ancienExiste := commandeDeCompte, runCommand, commandExists
	commandExists = func(string) bool { return true }
	commandeDeCompte = func(_ time.Duration, nom string, args ...string) (string, error) {
		if nom != "chage" {
			return "", fmt.Errorf("commande inattendue : %s", nom)
		}
		f.appels = append(f.appels, append([]string(nil), args...))
		for i := 0; i+1 < len(args); i++ {
			switch args[i] {
			case "-M":
				f.max = args[i+1]
			case "-W":
				f.warn = args[i+1]
			}
		}
		return "", nil
	}
	runCommand = func(nom string, args ...string) (string, error) {
		if nom == "chage" && len(args) == 2 && args[0] == "-l" {
			return "Last password change\t\t\t\t\t: Oct 07, 2026\n" +
				"Password expires\t\t\t\t\t: never\n" +
				"Password inactive\t\t\t\t\t: never\n" +
				"Account expires\t\t\t\t\t\t: never\n" +
				"Minimum number of days between password change\t\t: 0\n" +
				"Maximum number of days between password change\t\t: " + f.max + "\n" +
				"Number of days of warning before password expires\t: " + f.warn, nil
		}
		return ancienneLecture(nom, args...)
	}
	t.Cleanup(func() { commandeDeCompte, runCommand, commandExists = ancienne, ancienneLecture, ancienExiste })
}

func TestLeVieillissementDuMotDePasseEstVerifie(t *testing.T) {
	nom, _ := compteDEssai(t)
	chage := &fauxChage{max: "99999", warn: "7"}
	chage.installer(t)

	politique := politiqueU(nom, moduleU(ModuleUserPasswordPolicy, "mdp", map[string]string{
		"max_age_days": "90", "warn_days": "14"}))
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	attente := attenteDe(t, etat, CheckPasswordAging)
	if attente.Target != nom || attente.Expect != "max=90,warn=14" {
		t.Fatalf("attente = %+v, attendu le compte et « max=90,warn=14 »", attente)
	}
	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() || constat.Checked != 1 {
		t.Fatalf("juste apres l'application : %d verifie(s), %+v", constat.Checked, constat.Items)
	}

	// Un administrateur local desserre l'expiration.
	chage.max = "99999"
	item := unSeulEcart(t, scanFromState(etat, ScopeUser, nom), DriftSystemState, "age maximal : 90 attendu, 99999 constate")
	if item.StateKey != "mdp" {
		t.Errorf("ecart attribue a %q", item.StateKey)
	}
	chage.max, chage.warn = "90", "7"
	unSeulEcart(t, scanFromState(etat, ScopeUser, nom), DriftSystemState, "delai d'avertissement : 14 attendu, 7 constate")

	// « never » n'est pas un nombre : écart NOMMÉ, pas conformité par défaut.
	chage.max, chage.warn = "never", "14"
	unSeulEcart(t, scanFromState(etat, ScopeUser, nom), DriftSystemState, "age maximal : 90 attendu, inconnu constate")
}

// Seul ce que le module fixe est vérifié — et le changement forcé ne l'est
// jamais : il se consomme à la connexion.
func TestSeulCeQueLeModuleFixeEstVerifie(t *testing.T) {
	nom, _ := compteDEssai(t)
	chage := &fauxChage{max: "99999", warn: "7"}
	chage.installer(t)
	// loginShellOf lit le vrai passwd : le compte qui lance les tests a un shell.

	etat, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleUserPasswordPolicy, "mdp", map[string]string{
		"warn_days": "14"})), nil)
	exigerApplique(t, rapport)
	if attente := attenteDe(t, etat, CheckPasswordAging); attente.Expect != "warn=14" {
		t.Fatalf("attente = %q, attendu « warn=14 » : l'age maximal n'a pas ete fixe par le module", attente.Expect)
	}
	// L'âge maximal bouge, et personne ne l'a demandé : pas un écart.
	chage.max = "30"
	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("une facette que la politique ne fixe pas est signalee : %+v", constat.Items)
	}

	etat, rapport = appliquer(t, politiqueU(nom, moduleU(ModuleUserPasswordPolicy, "force", map[string]string{
		"force_change": "true"})), nil)
	if rapport.Modules[0].Result == ResultApplied && len(etat.Checks) != 0 {
		t.Fatalf("le changement force a declare une attente (%+v) : la personne qui a obei "+
			"serait en ecart a chaque connexion", etat.Checks)
	}
}

// ---------------------------------------------------------------------------
// user_cron
// ---------------------------------------------------------------------------

// fauxSystemctl tient lieu de `runuser -u <compte> -- systemctl --user …` : il
// fait ce que systemd fait sur le disque — poser ou retirer le lien
// d'activation — et rien d'autre. Le vrai exige le bus d'une session ouverte.
func fauxSystemctl(t *testing.T, home string, repondre bool) *[][]string {
	t.Helper()
	var appels [][]string
	ancienne, ancienExiste := commandeDeCompte, commandExists
	commandExists = func(string) bool { return true }
	commandeDeCompte = func(_ time.Duration, nom string, args ...string) (string, error) {
		appels = append(appels, append([]string{nom}, args...))
		if !repondre {
			return "", fmt.Errorf("Failed to connect to bus: No medium found")
		}
		unites := filepath.Join(home, ".config", "systemd", "user")
		for i, a := range args {
			if a == "enable" || a == "disable" {
				timer := args[len(args)-1]
				lien := filepath.Join(unites, "timers.target.wants", timer)
				if a == "enable" {
					_ = os.MkdirAll(filepath.Dir(lien), 0o755)
					_ = os.Remove(lien)
					_ = os.Symlink(filepath.Join(unites, timer), lien)
				} else {
					_ = os.Remove(lien)
				}
				_ = i
			}
		}
		return "", nil
	}
	t.Cleanup(func() { commandeDeCompte, commandExists = ancienne, ancienExiste })
	return &appels
}

// idDeTache rend une tâche du catalogue de l'agent (voir cronCommandFor).
func idDeTache(t *testing.T) string {
	t.Helper()
	const id = "report_disk_usage"
	if _, err := cronCommandFor(id); err != nil {
		t.Skipf("tache %s absente du catalogue : %v", id, err)
	}
	return id
}

func TestLActivationDUnTimerEstVerifiee(t *testing.T) {
	nom, home := compteDEssai(t)
	fauxSystemctl(t, home, true)
	id := idDeTache(t)
	timer := "vaultaire-" + id + ".timer"
	lien := filepath.Join(home, ".config", "systemd", "user", "timers.target.wants", timer)

	politique := politiqueU(nom, moduleU(ModuleUserCron, "tache", map[string]string{
		"command_id": id, "schedule": "0 3 * * *"}))
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	if attente := attenteDe(t, etat, CheckUserTimer); attente.Target != lien || attente.Expect != "etat=actif" {
		t.Fatalf("attente = %+v", attente)
	}
	// Deux unités à l'inventaire, plus l'activation.
	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() || constat.Checked != 3 {
		t.Fatalf("juste apres l'application : %d verifie(s), %+v", constat.Checked, constat.Items)
	}

	// LE cas du point : « systemctl --user disable ». Les deux unités sont
	// intactes — l'inventaire des fichiers ne voit rien — et la tâche ne part plus.
	if err := os.Remove(lien); err != nil {
		t.Fatal(err)
	}
	constat := scanFromState(etat, ScopeUser, nom)
	unSeulEcart(t, constat, DriftSystemState, "desactive")
	if modules := corriger(etat, constat); len(modules) != 1 || modules[0] != "tache" {
		t.Fatalf("modules a rejouer = %v", modules)
	}
	etat2, rapport2 := appliquer(t, politique, etat)
	exigerApplique(t, rapport2)
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("apres reapplication : %+v", constat.Items)
	}

	// Masqué : le lien existe, et désigne /dev/null.
	_ = os.Remove(lien)
	if err := os.Symlink("/dev/null", lien); err != nil {
		t.Fatal(err)
	}
	unSeulEcart(t, scanFromState(etat2, ScopeUser, nom), DriftSystemState, "designe /dev/null")

	// Un lien relatif, comme en écrivent d'autres versions de systemd : conforme.
	_ = os.Remove(lien)
	if err := os.Symlink("../"+timer, lien); err != nil {
		t.Fatal(err)
	}
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("un lien d'activation relatif est signale : %+v", constat.Items)
	}

	// Une cible d'un autre nom : c'est le NOM de l'entrée que systemd lit. On
	// n'invente pas un écart sur ce qu'on ne sait pas être un défaut.
	_ = os.Remove(lien)
	if err := os.Symlink("../autre-chose.timer", lien); err != nil {
		t.Fatal(err)
	}
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("la cible du lien est comparee a un nom : %+v", constat.Items)
	}

	// Remplacé par un fichier : on ne sait pas ce que systemd en fera. Ni
	// conforme, ni en écart — et rien n'est rejoué sur une incertitude.
	_ = os.Remove(lien)
	if err := os.WriteFile(lien, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	incertain := scanFromState(etat2, ScopeUser, nom)
	unSeulEcart(t, incertain, DriftUnverifiable, "etat incertain")
	if modules := incertain.ModulesConcerned(); len(modules) != 0 {
		t.Fatalf("modules a rejouer = %v sur une incertitude", modules)
	}
}

// Sans bus, l'activation échoue : le module le dit, et ne déclare PAS une
// attente qu'il n'a pas obtenue.
func TestUneActivationManqueeNeDeclareRien(t *testing.T) {
	nom, home := compteDEssai(t)
	fauxSystemctl(t, home, false)
	etat, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleUserCron, "tache", map[string]string{
		"command_id": idDeTache(t), "schedule": "0 3 * * *"})), nil)
	if rapport.Modules[0].Result != ResultFailed {
		t.Fatalf("resultat = %s, attendu un echec", rapport.Modules[0].Result)
	}
	for _, c := range etat.Checks {
		if c.Kind == CheckUserTimer {
			t.Fatalf("une attente d'activation est declaree alors que l'activation a echoue : %+v", c)
		}
	}
}

// Une tâche retirée : le lien d'activation part avec elle, même hors session,
// et sa réapparition est vue.
func TestUneTacheRetireeEmporteSonActivation(t *testing.T) {
	nom, home := compteDEssai(t)
	id := idDeTache(t)
	timer := "vaultaire-" + id + ".timer"
	lien := filepath.Join(home, ".config", "systemd", "user", "timers.target.wants", timer)

	fauxSystemctl(t, home, true)
	etat, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleUserCron, "tache", map[string]string{
		"command_id": id, "schedule": "0 3 * * *"})), nil)
	exigerApplique(t, rapport)

	// Le bus ne répond plus : « disable » échoue, comme hors session.
	fauxSystemctl(t, home, false)
	retrait := politiqueU(nom, moduleU(ModuleUserCron, "tache", map[string]string{
		"command_id": id, "state": "absent"}))
	retrait.Fingerprint = "politique-2"
	retrait.Modules[0].Fingerprint = "fp-tache-absent"
	etat2, rapport2 := appliquer(t, retrait, etat)
	exigerApplique(t, rapport2)

	if _, err := os.Lstat(lien); err == nil {
		t.Fatal("le lien d'activation est reste, pendant vers une unite supprimee : " +
			"« disable » n'a pas repondu et personne ne l'a retire")
	}
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("apres le retrait : %+v", constat.Items)
	}
	if err := os.MkdirAll(filepath.Dir(lien), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nulle/part", lien); err != nil {
		t.Fatal(err)
	}
	constat := scanFromState(etat2, ScopeUser, nom)
	if len(constat.Items) != 1 || constat.Items[0].Kind != DriftReappeared || constat.Items[0].Path != lien {
		t.Fatalf("ecarts = %+v, attendu la reapparition du lien d'activation", constat.Items)
	}
}

// ---------------------------------------------------------------------------
// Le scan des fichiers, sans suivre un seul lien
// ---------------------------------------------------------------------------

func etatAvecUnFichier(t *testing.T, nom string) (*ScopeState, *Policy) {
	t.Helper()
	politique := politiqueU(nom, moduleU(ModuleFileDeploy, "conf", map[string]string{
		"path": "/%h/.config/app/app.conf", "content": "cle = valeur\n", "mode": "0644"}))
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)
	return etat, politique
}

// LE cas du point : un RÉPERTOIRE du chemin devient un lien, vers un dossier où
// se trouve un fichier identique. Par chemin, root hachait ce fichier-là et
// concluait « conforme ».
func TestUnRepertoireDevenuLienNEstPlusTraverseParLeScan(t *testing.T) {
	nom, home := compteDEssai(t)
	etat, _ := etatAvecUnFichier(t, nom)

	ailleurs := t.TempDir()
	if err := os.WriteFile(filepath.Join(ailleurs, "app.conf"), []byte("cle = valeur\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(home, ".config", "app")
	if err := os.RemoveAll(app); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ailleurs, app); err != nil {
		t.Fatal(err)
	}
	// Preuve que l'ancien chemin se trompait : par le chemin, le fichier se lit,
	// et son contenu est celui de la politique.
	if h, ok := HashFile(filepath.Join(app, "app.conf")); !ok || h != etat.Files[filepath.Join(app, "app.conf")].SHA256 {
		t.Fatal("preparation : le fichier au bout du lien devrait se lire comme celui de la politique")
	}

	constat := scanFromState(etat, ScopeUser, nom)
	unSeulEcart(t, constat, DriftModified, "un repertoire du chemin est un lien symbolique")
	if constat.Checked != 1 {
		t.Errorf("%d element(s) verifie(s), attendu 1", constat.Checked)
	}
}

func TestLeScanDUnHomeReconnaitCeQuiNEstPlusLeFichierDepose(t *testing.T) {
	cas := []struct {
		nom      string
		abimer   func(t *testing.T, fichier string)
		genre    DriftKind
		fragment string
	}{
		{"lien a la place du fichier", func(t *testing.T, f string) {
			cible := filepath.Join(t.TempDir(), "x")
			_ = os.WriteFile(cible, []byte("cle = valeur\n"), 0o644)
			_ = os.Remove(f)
			if err := os.Symlink(cible, f); err != nil {
				t.Fatal(err)
			}
		}, DriftModified, "remplace par un lien symbolique"},
		{"repertoire a la place du fichier", func(t *testing.T, f string) {
			_ = os.Remove(f)
			if err := os.Mkdir(f, 0o755); err != nil {
				t.Fatal(err)
			}
		}, DriftModified, "autre chose qu'un fichier"},
		// Un tube sans écrivain : une lecture ordinaire y resterait pendue, et
		// l'ouverture de session avec elle.
		{"tube a la place du fichier", func(t *testing.T, f string) {
			_ = os.Remove(f)
			if err := syscall.Mkfifo(f, 0o644); err != nil {
				t.Skipf("mkfifo : %v", err)
			}
		}, DriftModified, "autre chose qu'un fichier"},
		{"contenu modifie", func(t *testing.T, f string) {
			if err := os.WriteFile(f, []byte("cle = autre\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, DriftModified, "contenu modifie"},
		// Cent mébioctets creux : dit modifié sans être lu.
		{"fichier demesure", func(t *testing.T, f string) {
			if err := os.Truncate(f, 100*1024*1024); err != nil {
				t.Fatal(err)
			}
		}, DriftModified, "contenu modifie"},
		{"mode change", func(t *testing.T, f string) {
			if err := os.Chmod(f, 0o666); err != nil {
				t.Fatal(err)
			}
		}, DriftPermissions, "mode 0666 attendu 0644"},
		{"fichier supprime", func(t *testing.T, f string) { _ = os.Remove(f) }, DriftMissing, "fichier supprime"},
		{"dossier supprime", func(t *testing.T, f string) { _ = os.RemoveAll(filepath.Dir(f)) }, DriftMissing, "fichier supprime"},
	}
	for _, cs := range cas {
		t.Run(cs.nom, func(t *testing.T) {
			nom, home := compteDEssai(t)
			etat, _ := etatAvecUnFichier(t, nom)
			fichier := filepath.Join(home, ".config", "app", "app.conf")
			cs.abimer(t, fichier)

			fini := make(chan DriftReport, 1)
			go func() { fini <- scanFromState(etat, ScopeUser, nom) }()
			select {
			case constat := <-fini:
				unSeulEcart(t, constat, cs.genre, cs.fragment)
			case <-time.After(10 * time.Second):
				t.Fatal("le scan ne rend pas la main : une ouverture de session resterait pendue")
			}
		})
	}
}

// Un fichier passé à un AUTRE compte — un lien physique, un chown oublié — n'est
// plus le fichier que la politique a posé, même si son contenu se lit pareil.
func TestUnFichierDUnAutreCompteEstSignale(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changer le proprietaire d'un fichier demande root")
	}
	nom, home := compteDEssai(t)
	etat, _ := etatAvecUnFichier(t, nom)
	fichier := filepath.Join(home, ".config", "app", "app.conf")
	if err := os.Chown(fichier, 65534, 65534); err != nil {
		t.Skipf("chown : %v", err)
	}
	unSeulEcart(t, scanFromState(etat, ScopeUser, nom), DriftModified, "appartient a l'uid 65534")
}

// Un compte qui n'existe plus : on ne sait pas où regarder. Incertitude, et
// donc rien de rejoué.
func TestUnCompteIntrouvableNeFaitRienRejouer(t *testing.T) {
	nom, _ := compteDEssai(t)
	etat, _ := etatAvecUnFichier(t, nom)

	constat := scanFromState(etat, ScopeUser, "compte-qui-n-existe-pas@acme.lan")
	if len(constat.Items) != 1 || constat.Items[0].Kind != DriftUnverifiable {
		t.Fatalf("ecarts = %+v, attendu une incertitude", constat.Items)
	}
	if modules := constat.ModulesConcerned(); len(modules) != 0 {
		t.Errorf("modules a rejouer = %v : on ne rejoue rien sur une incertitude", modules)
	}
}

// La portée MACHINE garde ses chemins : des fichiers gérés par une politique y
// sont légitimement des liens (/etc/resolv.conf), et les suivre est voulu.
func TestLaPorteeMachineSuitToujoursLesLiens(t *testing.T) {
	d := t.TempDir()
	reel := filepath.Join(d, "reel.conf")
	lien := filepath.Join(d, "lien.conf")
	if err := os.WriteFile(reel, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(reel, lien); err != nil {
		t.Fatal(err)
	}
	h, _ := HashFile(reel)
	etat := &ScopeState{Files: map[string]FileState{lien: {SHA256: h, Mode: 0o644, StateKey: "m"}}}
	if constat := scanFromState(etat, ScopeMachine, ""); !constat.Conforming() || constat.Checked != 1 {
		t.Fatalf("un lien gere en portee machine est signale : %+v", constat.Items)
	}
}

// ---------------------------------------------------------------------------
// Le vérificateur d'ACL, par descripteur
// ---------------------------------------------------------------------------

func TestLACLDUnHomeSeVerifieParDescripteur(t *testing.T) {
	exigerCommande(t, "setfacl")
	exigerCommande(t, "getfacl")
	nom, home := compteDEssai(t)
	cible := filepath.Join(home, "partage")
	if err := os.Mkdir(cible, 0o750); err != nil {
		t.Fatal(err)
	}
	politique := politiqueU(nom, moduleU(ModuleFileACL, "acl", map[string]string{
		"path": "/%h/partage", "kind": "user", "target": nom, "permissions": "r-x"}))
	etat, rapport := appliquer(t, politique, nil)
	if rapport.Modules[0].Result != ResultApplied {
		if strings.Contains(rapport.Modules[0].Detail, "Operation not supported") {
			t.Skip("ce systeme de fichiers ne porte pas d'ACL")
		}
		t.Fatalf("%s — %s", rapport.Modules[0].Result, rapport.Modules[0].Detail)
	}

	// getfacl reçoit un descripteur, pas le chemin.
	var arguments [][]string
	ancienne := runCommand
	runCommand = func(nomCmd string, args ...string) (string, error) {
		if nomCmd == "getfacl" {
			arguments = append(arguments, append([]string(nil), args...))
		}
		return ancienne(nomCmd, args...)
	}
	t.Cleanup(func() { runCommand = ancienne })

	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() || constat.Checked != 1 {
		t.Fatalf("juste apres l'application : %d verifie(s), %+v", constat.Checked, constat.Items)
	}
	if len(arguments) != 1 || !strings.HasPrefix(arguments[0][len(arguments[0])-1], "/proc/") {
		t.Fatalf("getfacl a recu %v : sous un HOME il doit recevoir un descripteur", arguments)
	}

	// LE cas du point : le dossier devient un lien vers un autre, qui porte la
	// MÊME entrée. Par chemin, getfacl suivait le lien et concluait « conforme ».
	ailleurs := t.TempDir()
	if sortie, err := exec.Command("setfacl", "-m", "u:"+nom+":r-x", ailleurs).CombinedOutput(); err != nil {
		t.Fatalf("setfacl : %v (%s)", err, sortie)
	}
	if err := os.Remove(cible); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ailleurs, cible); err != nil {
		t.Fatal(err)
	}
	if acl := aclDe(t, cible); !strings.Contains(acl, "user:"+nom+":r-x") {
		t.Fatalf("preparation : par le chemin, l'entree devrait se lire au bout du lien :\n%s", acl)
	}
	arguments = nil
	unSeulEcart(t, scanFromState(etat, ScopeUser, nom), DriftSystemState, "n'est plus un fichier ou un repertoire ordinaire du compte")
	if len(arguments) != 0 {
		t.Errorf("getfacl a ete lance sur un chemin suspect : %v", arguments)
	}

	// Le dossier disparaît : l'entrée avec lui.
	if err := os.Remove(cible); err != nil {
		t.Fatal(err)
	}
	unSeulEcart(t, scanFromState(etat, ScopeUser, nom), DriftSystemState, "a disparu")
}

// En portée machine, le vérificateur d'ACL garde le chemin : rien ne change.
func TestLACLDeLaMachineSeVerifieParChemin(t *testing.T) {
	var arguments [][]string
	ancienne, ancienExiste := runCommand, commandExists
	commandExists = func(string) bool { return true }
	runCommand = func(nomCmd string, args ...string) (string, error) {
		arguments = append(arguments, append([]string{nomCmd}, args...))
		return "user::rwx\nuser:alice:r-x\ngroup::r-x\nmask::r-x\nother::---\n", nil
	}
	t.Cleanup(func() { runCommand, commandExists = ancienne, ancienExiste })

	conforme, detail, err := verifierACL(SystemCheck{Kind: CheckFileACL, Target: "/srv/partage|u:alice", Expect: "r-x"})
	if err != nil || !conforme {
		t.Fatalf("conforme=%v detail=%q err=%v", conforme, detail, err)
	}
	if len(arguments) != 1 || arguments[0][len(arguments[0])-1] != "/srv/partage" {
		t.Fatalf("getfacl a recu %v, attendu le chemin /srv/partage", arguments)
	}
}
