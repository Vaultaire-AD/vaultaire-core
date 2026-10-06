//go:build linux

package gpo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TO-DO 162 — les deux appliqueurs du scope utilisateur qui passaient encore un
// CHEMIN à une commande lancée en root.
//
// Le point 97 a fermé l'écriture et la création de répertoire. `setfacl` et
// `git config` étaient restés : l'un et l'autre suivent les liens de l'argument
// qu'on leur donne, sur un dossier que l'utilisateur contrôle. Ces tests lancent
// les VRAIES commandes ; ils sont sautés sur une machine qui ne les a pas.

func exigerCommande(t *testing.T, nom string) {
	t.Helper()
	if _, err := exec.LookPath(nom); err != nil {
		t.Skipf("%s absent de cette machine", nom)
	}
}

func aclDe(t *testing.T, chemin string) string {
	t.Helper()
	sortie, err := exec.Command("getfacl", "--absolute-names", "--omit-header", chemin).CombinedOutput()
	if err != nil {
		t.Fatalf("getfacl %s : %v (%s)", chemin, err, sortie)
	}
	return string(sortie)
}

// espionnerSetfacl relève les arguments reçus par `setfacl`, et laisse la
// commande s'exécuter.
func espionnerSetfacl(t *testing.T) *[][]string {
	t.Helper()
	var appels [][]string
	ancienne := runCommand
	runCommand = func(nom string, args ...string) (string, error) {
		if nom == "setfacl" {
			appels = append(appels, append([]string(nil), args...))
		}
		return ancienne(nom, args...)
	}
	t.Cleanup(func() { runCommand = ancienne })
	return &appels
}

func TestUneACLSousUnHomeSePoseParDescripteur(t *testing.T) {
	exigerCommande(t, "setfacl")
	exigerCommande(t, "getfacl")
	nom, home := compteDEssai(t)
	cible := filepath.Join(home, "partage.txt")
	if err := os.WriteFile(cible, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	appels := espionnerSetfacl(t)

	_, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleFileACL, "acl", map[string]string{
		"path": "/%h/partage.txt", "kind": "user", "target": nom, "permissions": "r--"})), nil)
	if rapport.Modules[0].Result != ResultApplied {
		if strings.Contains(rapport.Modules[0].Detail, "Operation not supported") {
			t.Skip("ce systeme de fichiers ne porte pas d'ACL")
		}
		t.Fatalf("%s — %s", rapport.Modules[0].Result, rapport.Modules[0].Detail)
	}

	if acl := aclDe(t, cible); !strings.Contains(acl, "user:"+nom+":r--") {
		t.Errorf("l'ACL n'est pas posee :\n%s", acl)
	}
	if len(*appels) != 1 {
		t.Fatalf("%d appel(s) a setfacl, attendu 1", len(*appels))
	}
	dernier := (*appels)[0][len((*appels)[0])-1]
	if !strings.HasPrefix(dernier, "/proc/") {
		t.Errorf("setfacl a recu le chemin %q : sous un HOME il doit recevoir un descripteur, "+
			"le chemin peut etre remplace entre le controle et l'appel", dernier)
	}
}

// LE cas du point : la cible est devenue un lien vers un fichier d'ailleurs.
func TestUneACLNeSuitPasUnLienPlanteSousUnHome(t *testing.T) {
	exigerCommande(t, "setfacl")
	exigerCommande(t, "getfacl")
	nom, home := compteDEssai(t)
	victime := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(victime, []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	avant := aclDe(t, victime)
	if err := os.Symlink(victime, filepath.Join(home, "partage.txt")); err != nil {
		t.Fatalf("%v", err)
	}
	appels := espionnerSetfacl(t)

	_, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleFileACL, "acl", map[string]string{
		"path": "/%h/partage.txt", "kind": "user", "target": nom, "permissions": "rwx"})), nil)
	if rapport.Modules[0].Result != ResultFailed {
		t.Fatalf("resultat = %s, attendu un echec", rapport.Modules[0].Result)
	}
	if len(*appels) != 0 {
		t.Errorf("setfacl a ete lance : %v", *appels)
	}
	if apres := aclDe(t, victime); apres != avant {
		t.Errorf("l'ACL du fichier hors du HOME a change :\n%s", apres)
	}
}

// En récursif, un lien rencontré PENDANT la descente ne doit pas emmener
// `setfacl` hors du dossier.
func TestUneACLRecursiveNeSortPasDuHome(t *testing.T) {
	exigerCommande(t, "setfacl")
	exigerCommande(t, "getfacl")
	nom, home := compteDEssai(t)
	dehors := t.TempDir()
	victime := filepath.Join(dehors, "precieux")
	if err := os.WriteFile(victime, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	avant := aclDe(t, victime)

	dossier := filepath.Join(home, "partage")
	if err := os.Mkdir(dossier, 0o700); err != nil {
		t.Fatalf("%v", err)
	}
	dedans := filepath.Join(dossier, "dedans.txt")
	if err := os.WriteFile(dedans, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.Symlink(dehors, filepath.Join(dossier, "sortie")); err != nil {
		t.Fatalf("%v", err)
	}

	appels := espionnerSetfacl(t)

	_, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleFileACL, "acl", map[string]string{
		"path": "/%h/partage", "kind": "user", "target": nom, "permissions": "r-x", "recursive": "true"})), nil)
	if rapport.Modules[0].Result != ResultApplied {
		if strings.Contains(rapport.Modules[0].Detail, "Operation not supported") {
			t.Skip("ce systeme de fichiers ne porte pas d'ACL")
		}
		t.Fatalf("%s — %s", rapport.Modules[0].Result, rapport.Modules[0].Detail)
	}
	if acl := aclDe(t, dedans); !strings.Contains(acl, "user:"+nom+":r-x") {
		t.Errorf("la recursion n'a pas atteint le contenu du dossier :\n%s", acl)
	}
	if apres := aclDe(t, victime); apres != avant {
		t.Errorf("la recursion est sortie du HOME par un lien :\n%s", apres)
	}

	// Le parcours physique est DEMANDÉ, pas seulement obtenu. `setfacl` écarte
	// de lui-même les liens rencontrés en descendant — c'est son défaut, et le
	// contrôle ci-dessus passerait sans « -P ». Mais un défaut se change d'une
	// version à l'autre ; ce qui protège un `HOME` doit être écrit.
	for _, appel := range *appels {
		if !argumentPresent(appel, "-P") {
			t.Errorf("setfacl recursif sans parcours physique : %v", appel)
		}
		if dernier := appel[len(appel)-1]; !strings.HasSuffix(dernier, "/.") {
			t.Errorf("la cible %q n'est pas un vrai repertoire pour setfacl : avec « -P », "+
				"un argument qui est un lien — celui de /proc l'est — est ecarte en entier", dernier)
		}
	}
}

func argumentPresent(liste []string, valeur string) bool {
	for _, v := range liste {
		if v == valeur {
			return true
		}
	}
	return false
}

// Un fichier d'un AUTRE compte sous le `HOME` : ni désigné à une commande, ni
// relu. C'est ce qu'est un lien physique vers un fichier de root — un fichier
// parfaitement ordinaire, sous un répertoire parfaitement réel.
//
// Demande root, pour pouvoir donner un fichier à quelqu'un d'autre.
func TestUnFichierDUnAutreCompteNEstNiDesigneNiRelu(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("ce test doit pouvoir changer le proprietaire d'un fichier")
	}
	_, home := compteDEssai(t)
	etranger := filepath.Join(home, "pas-a-moi")
	if err := os.WriteFile(etranger, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.Chown(etranger, 65534, 65534); err != nil {
		t.Fatalf("%v", err)
	}

	if objet, err := designerSousHome(home, etranger, 0); err == nil {
		objet.Close()
		t.Error("un fichier d'un autre compte a ete designe a une commande")
	}
	if contenu, _, err := lireFichierUtilisateur(home, etranger, 0); err == nil {
		t.Errorf("un fichier d'un autre compte a ete relu : %q", contenu)
	}
}

func TestGitConfigTravailleSurUneCopie(t *testing.T) {
	exigerCommande(t, "git")
	nom, home := compteDEssai(t)
	gitconfig := filepath.Join(home, ".gitconfig")
	if err := os.WriteFile(gitconfig, []byte("[alias]\n\tst = status\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}

	etat, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleUserGitConfig, "git-nom", map[string]string{
		"key": "user.name", "value": "Alice Martin"})), nil)
	exigerApplique(t, rapport)

	contenu, _ := os.ReadFile(gitconfig)
	if !strings.Contains(string(contenu), "name = Alice Martin") || !strings.Contains(string(contenu), "st = status") {
		t.Errorf("le fichier ne porte pas la cle ET ce que l'utilisateur y avait :\n%s", contenu)
	}
	if _, connu := etat.Files[gitconfig]; connu {
		t.Error(".gitconfig est inventorie en entier : chaque `git config` de l'utilisateur serait une derive")
	}
	if restes, _ := filepath.Glob(filepath.Join(home, "*.lock")); len(restes) != 0 {
		t.Errorf("git a travaille dans le HOME : %v", restes)
	}

	// Et le retrait.
	retire := moduleU(ModuleUserGitConfig, "git-nom", map[string]string{"key": "user.name", "state": "absent"})
	retire.Fingerprint = "fp-git-nom-2"
	_, rapport = appliquer(t, politiqueU(nom, retire), etat)
	exigerApplique(t, rapport)
	contenu, _ = os.ReadFile(gitconfig)
	if strings.Contains(string(contenu), "Alice Martin") || !strings.Contains(string(contenu), "st = status") {
		t.Errorf("apres retrait :\n%s", contenu)
	}
}

// LE cas du point : `~/.gitconfig` est un lien vers un fichier qui n'existe pas
// encore, dans un répertoire que seul root écrit. L'ancien code le faisait
// CRÉER par git, puis le DONNAIT à l'utilisateur par chown.
func TestGitConfigNeSuitPasUnLien(t *testing.T) {
	exigerCommande(t, "git")
	nom, home := compteDEssai(t)
	ailleurs := t.TempDir()
	victime := filepath.Join(ailleurs, "ld.so.preload")
	if err := os.Symlink(victime, filepath.Join(home, ".gitconfig")); err != nil {
		t.Fatalf("%v", err)
	}

	_, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleUserGitConfig, "git-nom", map[string]string{
		"key": "user.name", "value": "Alice Martin"})), nil)
	if rapport.Modules[0].Result != ResultFailed {
		t.Fatalf("resultat = %s, attendu un echec", rapport.Modules[0].Result)
	}
	if entrees, _ := os.ReadDir(ailleurs); len(entrees) != 0 {
		t.Errorf("quelque chose a ete cree a travers le lien, hors du HOME : %v", entrees)
	}
}
