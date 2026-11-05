//go:build linux

package gpo

import (
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// TO-DO 135 — le scope utilisateur entre dans l'inventaire.
//
// # Ce que ces tests ont de différent
//
// `TestLaDeriveEstDetecteeDansUnHome` fabriquait son `ScopeState` à la main, en
// y inscrivant les fichiers que le vrai chemin n'inscrivait JAMAIS. Il vérifiait
// la règle du scan, pas ce qui la nourrit — et c'est ce qui a laissé passer le
// défaut : la règle était juste, l'inventaire était vide.
//
// Ceux-ci partent du VRAI appliqueur. Une politique est appliquée dans un
// dossier personnel réel, l'état est construit par `BuildScopeState`, le
// dossier est défait comme un utilisateur le déferait, et le scan doit le voir.
// Aucune entrée d'inventaire n'est écrite par le test.

func moduleU(typ, cle string, params map[string]string) Module {
	return Module{Type: typ, Scope: ScopeUser, StateKey: cle, Fingerprint: "fp-" + cle, Params: params}
}

func politiqueU(nom string, modules ...Module) *Policy {
	return &Policy{Name: "essai", Scope: ScopeUser, Username: nom, Version: 1,
		Fingerprint: "politique-1", Modules: modules}
}

// appliquer déroule ce que fait runCycle, sans le réseau ni /var/lib/vaultaire.
func appliquer(t *testing.T, politique *Policy, precedent *ScopeState) (*ScopeState, Report) {
	t.Helper()
	rapport := ApplyPolicy(politique, precedent)
	return BuildScopeState(politique, precedent, rapport), rapport
}

// corriger déroule ce que fait EnforceDrift, sans /var/lib/vaultaire : les
// modules concernés perdent leur empreinte, et la politique avec eux.
func corriger(etat *ScopeState, rapport DriftReport) []string {
	modules := rapport.ModulesConcerned()
	for _, cle := range modules {
		etat.ForgetModule(cle)
	}
	etat.Fingerprint = ""
	return modules
}

func exigerApplique(t *testing.T, rapport Report) {
	t.Helper()
	for _, m := range rapport.Modules {
		if m.Result != ResultApplied {
			t.Fatalf("module %s (%s) : %s — %s", m.ModuleType, m.StateKey, m.Result, m.Detail)
		}
	}
}

// LE test du point. Avant la correction, `etat.Files` était vide ici : le scan
// sortait sur « rien à comparer », n'émettait aucun rapport, et le cycle
// suivant recevait « politique inchangée ».
func TestUnFichierDeposeDansUnHomeEntreDansLInventaire(t *testing.T) {
	nom, home := compteDEssai(t)
	politique := politiqueU(nom,
		moduleU(ModuleFileDeploy, "charte", map[string]string{
			"path": "/%h/Documents/charte.txt", "content": "charte v1\n", "mode": "0640"}),
	)

	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	depose := filepath.Join(home, "Documents", "charte.txt")
	entree, connu := etat.Files[depose]
	if !connu {
		t.Fatalf("le fichier depose n'est pas dans l'inventaire (inventaire : %v) — "+
			"c'est le defaut du point 135 : le scan n'aura rien a comparer", cles(etat.Files))
	}
	if entree.StateKey != "charte" || entree.Mode != 0o640 || entree.SHA256 == "" {
		t.Errorf("entree = %+v, attendu attribuee a « charte », mode 0640, hachee", entree)
	}

	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() || constat.Checked == 0 {
		t.Fatalf("juste apres l'application : %d verifie(s), ecarts %v — attendu conforme et "+
			"au moins un element verifie", constat.Checked, constat.Items)
	}
}

// La recette du 30/09, première forme : l'utilisateur SUPPRIME le fichier.
func TestUnFichierSupprimeDansUnHomeEstDetectePuisRepose(t *testing.T) {
	nom, home := compteDEssai(t)
	politique := politiqueU(nom,
		moduleU(ModuleFileDeploy, "charte", map[string]string{
			"path": "/%h/Documents/charte.txt", "content": "charte v1\n"}),
		moduleU(ModuleFileDeploy, "autre", map[string]string{
			"path": "/%h/Documents/autre.txt", "content": "autre\n"}),
	)
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	depose := filepath.Join(home, "Documents", "charte.txt")
	if err := os.Remove(depose); err != nil {
		t.Fatalf("%v", err)
	}

	constat := scanFromState(etat, ScopeUser, nom)
	if len(constat.Items) != 1 || constat.Items[0].Kind != DriftMissing || constat.Items[0].Path != depose {
		t.Fatalf("ecarts = %+v, attendu un seul : %s supprime", constat.Items, depose)
	}
	if modules := corriger(etat, constat); len(modules) != 1 || modules[0] != "charte" {
		t.Fatalf("modules a rejouer = %v, attendu [charte] : le module intact n'a pas a l'etre", modules)
	}

	// Le cycle qui suit le scan : seul le module oublié est rejoué.
	etat2, rapport2 := appliquer(t, politique, etat)
	for _, m := range rapport2.Modules {
		attendu := ResultUnchanged
		if m.StateKey == "charte" {
			attendu = ResultApplied
		}
		if m.Result != attendu {
			t.Errorf("module %s : %s, attendu %s", m.StateKey, m.Result, attendu)
		}
	}
	if contenu, err := os.ReadFile(depose); err != nil || string(contenu) != "charte v1\n" {
		t.Fatalf("le fichier n'a pas ete repose : %q, %v", contenu, err)
	}
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Errorf("apres reapplication il reste des ecarts : %+v", constat.Items)
	}
	// Le module qui n'a pas été rejoué reste surveillé.
	if _, connu := etat2.Files[filepath.Join(home, "Documents", "autre.txt")]; !connu {
		t.Error("le fichier du module non rejoue a quitte l'inventaire")
	}
}

// Seconde forme : il le MODIFIE, ou en change les droits.
func TestUnFichierModifieDansUnHomeEstDetecte(t *testing.T) {
	nom, home := compteDEssai(t)
	politique := politiqueU(nom, moduleU(ModuleFileDeploy, "charte", map[string]string{
		"path": "/%h/charte.txt", "content": "charte v1\n", "mode": "0600"}))
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)
	depose := filepath.Join(home, "charte.txt")

	if err := os.WriteFile(depose, []byte("ce que je veux\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	if constat := scanFromState(etat, ScopeUser, nom); len(constat.Items) != 1 || constat.Items[0].Kind != DriftModified {
		t.Fatalf("contenu modifie : ecarts = %+v, attendu un « modified »", constat.Items)
	}

	if err := os.WriteFile(depose, []byte("charte v1\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.Chmod(depose, 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	if constat := scanFromState(etat, ScopeUser, nom); len(constat.Items) != 1 || constat.Items[0].Kind != DriftPermissions {
		t.Fatalf("droits elargis : ecarts = %+v, attendu un « permissions »", constat.Items)
	}
}

// Un fichier que la politique RETIRE d'un `HOME` : le recréer est un écart.
func TestUnFichierRetireDUnHomeEstSurveille(t *testing.T) {
	nom, home := compteDEssai(t)
	interdit := filepath.Join(home, ".netrc")
	if err := os.WriteFile(interdit, []byte("machine x login y password z\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}

	politique := politiqueU(nom, moduleU(ModuleFileDeploy, "sans-netrc", map[string]string{
		"path": "/%h/.netrc", "state": "absent"}))
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	if _, err := os.Lstat(interdit); !os.IsNotExist(err) {
		t.Fatalf("le fichier n'a pas ete retire : %v", err)
	}
	if entree := etat.Files[interdit]; !entree.Absent || entree.StateKey != "sans-netrc" {
		t.Fatalf("entree = %+v, attendu une absence attribuee au module", entree)
	}

	if err := os.WriteFile(interdit, []byte("revenu\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	if constat := scanFromState(etat, ScopeUser, nom); len(constat.Items) != 1 || constat.Items[0].Kind != DriftReappeared {
		t.Fatalf("ecarts = %+v, attendu un « reappeared »", constat.Items)
	}
}

// Les variables d'environnement d'un compte partagent un fichier. Le défaire
// doit faire rejouer TOUS les modules qui y écrivent : n'en rejouer qu'un
// rendrait un fichier où il manque les variables des autres, et ce fichier
// amputé deviendrait aussitôt la référence.
func TestLeFichierDEnvironnementEstPartageEntreSesModules(t *testing.T) {
	nom, home := compteDEssai(t)
	politique := politiqueU(nom,
		moduleU(ModuleUserEnv, "env-editor", map[string]string{"name": "EDITOR", "value": "vi"}),
		moduleU(ModuleUserEnv, "env-proxy", map[string]string{"name": "HTTPS_PROXY", "value": "http://proxy:3128"}),
	)
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	env := filepath.Join(home, userEnvFileName)
	entree, connu := etat.Files[env]
	if !connu {
		t.Fatalf("%s n'est pas dans l'inventaire", env)
	}
	if got := entree.proprietaires(); len(got) != 2 || got[0] != "env-editor" || got[1] != "env-proxy" {
		t.Fatalf("proprietaires = %v, attendu les deux modules", got)
	}

	if err := os.Remove(env); err != nil {
		t.Fatalf("%v", err)
	}
	constat := scanFromState(etat, ScopeUser, nom)
	modules := corriger(etat, constat)
	if len(modules) != 2 {
		t.Fatalf("modules a rejouer = %v, attendu les deux proprietaires du fichier", modules)
	}

	etat2, _ := appliquer(t, politique, etat)
	contenu, err := os.ReadFile(env)
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, attendu := range []string{"export EDITOR='vi'", "export HTTPS_PROXY='http://proxy:3128'"} {
		if !strings.Contains(string(contenu), attendu) {
			t.Errorf("apres reapplication il manque %q dans :\n%s", attendu, contenu)
		}
	}
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Errorf("ecarts apres reapplication : %+v", constat.Items)
	}
}

// Une ligne ajoutée à la main ne survit pas à la correction — et surtout elle
// n'entre pas dans la référence. L'ancien appliqueur recopiait les lignes qu'il
// ne reconnaissait pas « pour les modules voisins » : la correction d'une
// dérive consacrait ce qu'elle devait effacer.
func TestUneLigneAjouteeALEnvironnementNEstPasConsacree(t *testing.T) {
	nom, home := compteDEssai(t)
	politique := politiqueU(nom,
		moduleU(ModuleUserEnv, "env-editor", map[string]string{"name": "EDITOR", "value": "vi"}))
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	env := filepath.Join(home, userEnvFileName)
	f, err := os.OpenFile(env, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("%v", err)
	}
	_, _ = f.WriteString("export LD_PRELOAD='/tmp/x.so'\n")
	_ = f.Close()

	constat := scanFromState(etat, ScopeUser, nom)
	if constat.Conforming() {
		t.Fatal("la ligne ajoutee n'est pas vue")
	}
	corriger(etat, constat)
	etat2, _ := appliquer(t, politique, etat)

	contenu, _ := os.ReadFile(env)
	if strings.Contains(string(contenu), "LD_PRELOAD") {
		t.Errorf("la ligne ajoutee a survecu a la correction :\n%s", contenu)
	}
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Errorf("ecarts apres correction : %+v", constat.Items)
	}
}

// Une variable retirée de la politique disparaît à la réécriture suivante —
// ce que le commentaire de userEnvFileName promettait sans que le code le fasse.
func TestUneVariableRetireeDeLaPolitiqueQuitteLeFichier(t *testing.T) {
	nom, home := compteDEssai(t)
	editor := moduleU(ModuleUserEnv, "env-editor", map[string]string{"name": "EDITOR", "value": "vi"})
	proxy := moduleU(ModuleUserEnv, "env-proxy", map[string]string{"name": "HTTPS_PROXY", "value": "http://proxy:3128"})

	etat, _ := appliquer(t, politiqueU(nom, editor, proxy), nil)

	// Le module proxy quitte la politique, et celui de l'éditeur change.
	editor.Params["value"] = "nano"
	editor.Fingerprint = "fp-env-editor-2"
	etat2, _ := appliquer(t, politiqueU(nom, editor), etat)

	contenu, _ := os.ReadFile(filepath.Join(home, userEnvFileName))
	if strings.Contains(string(contenu), "HTTPS_PROXY") || !strings.Contains(string(contenu), "export EDITOR='nano'") {
		t.Errorf("fichier d'environnement inattendu :\n%s", contenu)
	}
	entree := etat2.Files[filepath.Join(home, userEnvFileName)]
	if got := entree.proprietaires(); len(got) != 1 || got[0] != "env-editor" {
		t.Errorf("proprietaires = %v, attendu le seul module restant", got)
	}
}

// Un fichier partagé dont UN propriétaire quitte la politique reste surveillé
// tant qu'un autre y écrit. Avec un propriétaire unique, retirer le dernier à
// avoir écrit faisait sortir le fichier de l'inventaire.
func TestUnFichierPartageResteSurveilleQuandUnProprietairePart(t *testing.T) {
	nom, home := compteDEssai(t)
	editor := moduleU(ModuleUserEnv, "env-editor", map[string]string{"name": "EDITOR", "value": "vi"})
	proxy := moduleU(ModuleUserEnv, "env-proxy", map[string]string{"name": "HTTPS_PROXY", "value": "http://proxy:3128"})
	etat, _ := appliquer(t, politiqueU(nom, editor, proxy), nil)

	// Le DERNIER à avoir écrit s'en va ; l'autre n'est pas rejoué.
	etat2, rapport := appliquer(t, politiqueU(nom, editor), etat)
	if rapport.Modules[0].Result != ResultUnchanged {
		t.Fatalf("le module restant a ete rejoue (%s) : ce test ne dit plus rien", rapport.Modules[0].Result)
	}
	entree, connu := etat2.Files[filepath.Join(home, userEnvFileName)]
	if !connu {
		t.Fatal("le fichier a quitte l'inventaire alors qu'un module y ecrit encore")
	}
	if entree.StateKey != "env-editor" || len(entree.Owners) != 0 {
		t.Errorf("entree = %+v, attendu le seul module restant, sans liste de proprietaires", entree)
	}
}

// Le `.bashrc` appartient à la personne. La politique n'y tient qu'un bloc :
// l'éditer n'est pas une dérive, retirer le bloc en est une.
func TestLeBlocDuBashrcEstSurveilleEtPasLeFichier(t *testing.T) {
	nom, home := compteDEssai(t)
	bashrc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(bashrc, []byte("alias ll='ls -l'\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	politique := politiqueU(nom,
		moduleU(ModuleUserEnv, "env-editor", map[string]string{"name": "EDITOR", "value": "vi"}))
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	if _, connu := etat.Files[bashrc]; connu {
		t.Fatal(".bashrc est inventorie EN ENTIER : chaque alias ajoute par l'utilisateur serait une derive")
	}
	if _, connu := etat.Checks[CheckFileBlock+"|"+bashrc+separateurBloc+blocEnvironnement]; !connu {
		t.Fatalf("aucune attente sur le bloc de .bashrc (attentes : %v)", clesAttentes(etat.Checks))
	}

	// La personne édite son fichier — avant et après le bloc.
	contenu, _ := os.ReadFile(bashrc)
	if !strings.Contains(string(contenu), "alias ll='ls -l'") {
		t.Fatalf("le contenu de l'utilisateur a ete perdu :\n%s", contenu)
	}
	if err := os.WriteFile(bashrc, []byte("export PS1='> '\n"+string(contenu)+"alias la='ls -a'\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("editer son .bashrc a ete pris pour une derive : %+v", constat.Items)
	}

	// Elle retire le bloc.
	if err := os.WriteFile(bashrc, []byte("alias ll='ls -l'\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	constat := scanFromState(etat, ScopeUser, nom)
	if len(constat.Items) != 1 || constat.Items[0].Kind != DriftSystemState {
		t.Fatalf("bloc retire : ecarts = %+v, attendu un ecart d'etat", constat.Items)
	}
	if modules := corriger(etat, constat); len(modules) != 1 || modules[0] != "env-editor" {
		t.Fatalf("modules a rejouer = %v", modules)
	}
	etat2, _ := appliquer(t, politique, etat)
	contenu, _ = os.ReadFile(bashrc)
	if !strings.Contains(string(contenu), vaultaireMarkerStart) || !strings.Contains(string(contenu), "alias ll='ls -l'") {
		t.Errorf("apres reapplication :\n%s", contenu)
	}
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Errorf("ecarts apres reapplication : %+v", constat.Items)
	}
}

// Même règle pour `~/.ssh/config` : un bloc par alias, le reste à la personne.
func TestLeBlocSSHEstSurveilleEtPasLeFichier(t *testing.T) {
	nom, home := compteDEssai(t)
	config := filepath.Join(home, ".ssh", "config")
	bastion := moduleU(ModuleUserSSHClientConfig, "ssh-bastion", map[string]string{
		"host_alias": "bastion", "hostname": "bastion.exemple.fr", "port": "2222"})
	politique := politiqueU(nom, bastion)
	etat, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	if _, connu := etat.Files[config]; connu {
		t.Fatal("~/.ssh/config est inventorie EN ENTIER")
	}

	contenu, _ := os.ReadFile(config)
	if err := os.WriteFile(config, append(contenu, []byte("\nHost perso\n    HostName chez.moi\n")...), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	if constat := scanFromState(etat, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("ajouter son propre hote a ete pris pour une derive : %+v", constat.Items)
	}

	modifie := strings.Replace(string(contenu), "bastion.exemple.fr", "pirate.exemple.fr", 1)
	if err := os.WriteFile(config, []byte(modifie), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	constat := scanFromState(etat, ScopeUser, nom)
	if len(constat.Items) != 1 || !strings.Contains(constat.Items[0].Detail, "modifie") {
		t.Fatalf("hote reel detourne : ecarts = %+v", constat.Items)
	}
}

// Le retrait d'un alias qui était seul retire le fichier — sans déclarer que
// le fichier doit rester absent. La personne qui crée ensuite son propre
// `~/.ssh/config` n'est pas en écart ; celle qui y remet le bloc, si.
func TestUnAliasRetireNInterditPasLeFichier(t *testing.T) {
	nom, home := compteDEssai(t)
	config := filepath.Join(home, ".ssh", "config")
	pose := moduleU(ModuleUserSSHClientConfig, "ssh-bastion", map[string]string{
		"host_alias": "bastion", "hostname": "bastion.exemple.fr"})
	etat, _ := appliquer(t, politiqueU(nom, pose), nil)
	bloc, _ := os.ReadFile(config)

	retire := moduleU(ModuleUserSSHClientConfig, "ssh-bastion", map[string]string{
		"host_alias": "bastion", "state": "absent"})
	retire.Fingerprint = "fp-ssh-bastion-absent"
	etat2, rapport := appliquer(t, politiqueU(nom, retire), etat)
	exigerApplique(t, rapport)

	if _, err := os.Lstat(config); !os.IsNotExist(err) {
		t.Fatalf("le fichier ou le bloc etait seul n'a pas ete retire : %v", err)
	}
	if _, connu := etat2.Files[config]; connu {
		t.Fatal("le fichier est inscrit comme devant rester absent : la personne ne pourrait plus avoir de ~/.ssh/config")
	}

	if err := os.WriteFile(config, []byte("Host perso\n    HostName chez.moi\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("creer son propre fichier a ete pris pour une derive : %+v", constat.Items)
	}

	if err := os.WriteFile(config, bloc, 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	if constat := scanFromState(etat2, ScopeUser, nom); len(constat.Items) != 1 {
		t.Fatalf("bloc retabli : ecarts = %+v, attendu un", constat.Items)
	}
}

// Ce qu'un module rejoué déclare REMPLACE ce qu'il déclarait. Sans cela, une
// attente que le module ne reproduit plus restait dans l'état pour toujours —
// ici celle d'un `.zshrc` que la personne a supprimé : écart signalé, module
// rejoué, écart toujours là, à chaque vérification.
func TestUneAttenteQuUnModuleNeReproduitPlusQuitteLEtat(t *testing.T) {
	nom, home := compteDEssai(t)
	zshrc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(zshrc, []byte("# zsh\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("# bash\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	politique := politiqueU(nom,
		moduleU(ModuleUserEnv, "env-editor", map[string]string{"name": "EDITOR", "value": "vi"}))
	etat, _ := appliquer(t, politique, nil)

	if err := os.Remove(zshrc); err != nil {
		t.Fatalf("%v", err)
	}
	constat := scanFromState(etat, ScopeUser, nom)
	if constat.Conforming() {
		t.Fatal("le fichier de demarrage supprime n'est pas vu")
	}
	corriger(etat, constat)
	etat2, _ := appliquer(t, politique, etat)

	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Fatalf("la correction ne converge pas : %+v", constat.Items)
	}
}

// Même règle pour un fichier : un module dont le chemin change cesse de
// répondre de l'ancien. Sans cela, l'ancien fichier resterait surveillé au nom
// d'un module qui ne l'écrit plus — le supprimer ferait rejouer ce module à
// chaque vérification, sans jamais le faire revenir.
func TestUnFichierQuUnModuleNEcritPlusQuitteLInventaire(t *testing.T) {
	nom, home := compteDEssai(t)
	charte := moduleU(ModuleFileDeploy, "charte", map[string]string{
		"path": "/%h/ancien.txt", "content": "charte\n"})
	etat, _ := appliquer(t, politiqueU(nom, charte), nil)

	charte.Params = map[string]string{"path": "/%h/nouveau.txt", "content": "charte\n"}
	charte.Fingerprint = "fp-charte-2"
	etat2, rapport := appliquer(t, politiqueU(nom, charte), etat)
	exigerApplique(t, rapport)

	if _, connu := etat2.Files[filepath.Join(home, "ancien.txt")]; connu {
		t.Error("l'ancien chemin est reste a l'inventaire")
	}
	if _, connu := etat2.Files[filepath.Join(home, "nouveau.txt")]; !connu {
		t.Error("le nouveau chemin n'est pas a l'inventaire")
	}
	_ = os.Remove(filepath.Join(home, "ancien.txt"))
	if constat := scanFromState(etat2, ScopeUser, nom); !constat.Conforming() {
		t.Errorf("supprimer l'ancien fichier est pris pour une derive : %+v", constat.Items)
	}
}

// Deux comptes qui ouvrent une session au même instant. Chacun doit retrouver
// SES fichiers dans SON état, et aucun de ceux de l'autre : avec l'inventaire
// global d'avant, le relevé de l'un voyait les écritures de l'autre.
func TestDeuxCyclesSimultanesNeSeMelangentPas(t *testing.T) {
	moi, err := user.Current()
	if err != nil {
		t.Skipf("compte courant illisible : %v", err)
	}

	const comptes = 8
	const tours = 40
	var groupe sync.WaitGroup
	erreurs := make(chan string, comptes*tours)

	for c := 0; c < comptes; c++ {
		home := t.TempDir()
		groupe.Add(1)
		go func(c int, home string) {
			defer groupe.Done()
			ctx := Context{Scope: ScopeUser, Username: moi.Username, HomeDir: home, inv: nouvelInventaire()}
			for i := 0; i < tours; i++ {
				m := moduleU(ModuleFileDeploy, "depot", map[string]string{
					"path": "/%h/fichier.txt", "content": "contenu\n"})
				issue := applyModule(ctx, m, nil)
				if issue.Result != ResultApplied {
					erreurs <- issue.Detail
					return
				}
				if len(issue.Files) != 1 {
					erreurs <- "module attribue de " + strings.Join(cles(issue.Files), ", ")
					return
				}
				for chemin := range issue.Files {
					if !strings.HasPrefix(chemin, home+"/") {
						erreurs <- "le compte de " + home + " s'est vu attribuer " + chemin
						return
					}
				}
			}
		}(c, home)
	}
	groupe.Wait()
	close(erreurs)
	for e := range erreurs {
		t.Error(e)
	}
}

// L'inventaire d'un compte n'est jamais celui de la machine, ni celui d'un
// autre compte : c'est ce qui rend le test précédent vrai pour ApplyPolicy, et
// pas seulement pour un contexte construit à la main.
func TestChaqueApplicationUtilisateurASonInventaire(t *testing.T) {
	a, b := inventairePour(ScopeUser), inventairePour(ScopeUser)
	if a == inventaireMachine || b == inventaireMachine {
		t.Fatal("une application utilisateur ecrit dans l'inventaire de la machine")
	}
	if a == b {
		t.Fatal("deux applications utilisateur partagent leur inventaire")
	}

	inventaireMachine.noterEcriture("/etc/essai", "x", 0o644)
	if inventairePour(ScopeMachine) != inventaireMachine {
		t.Fatal("le cycle machine n'ecrit plus dans son inventaire")
	}
	if len(manifestSnapshot()) != 0 {
		t.Error("l'inventaire de la machine n'est pas vide au debut d'une application : " +
			"une entree d'un cycle anterieur serait attribuee a un module de celui-ci")
	}
}

// Un état écrit avant que le scope utilisateur n'inventorie est rejoué une
// fois. Sans cela, un compte à la politique stable — « politique inchangée » à
// chaque connexion — n'aurait jamais eu d'inventaire.
func TestUnEtatAnterieurEstRejoueUneFois(t *testing.T) {
	ancien := &ScopeState{
		Fingerprint: "politique-1",
		Modules:     map[string]string{"charte": "fp-charte", "labo": "fp-labo"},
		Modes:       map[string]string{"labo": string(DriftAudit)},
	}
	if rejoues := ancien.oublierPourInventaire(); rejoues != 1 {
		t.Fatalf("%d module(s) a rejouer, attendu 1 — celui en audit ne se reecrit pas", rejoues)
	}
	if _, encore := ancien.Modules["charte"]; encore {
		t.Error("le module en enforce a garde son empreinte : il ne sera pas rejoue")
	}
	if _, encore := ancien.Modules["labo"]; !encore {
		t.Error("le module en AUDIT a perdu son empreinte : il serait reecrit, ce que l'audit exclut")
	}
	if ancien.Fingerprint != "" {
		t.Error("l'empreinte de politique est restee : le serveur repondra « inchangee » et rien ne sera rejoue")
	}

	nom, _ := compteDEssai(t)
	recent, _ := appliquer(t, politiqueU(nom, moduleU(ModuleFileDeploy, "charte", map[string]string{
		"path": "/%h/charte.txt", "content": "x\n"})), nil)
	if recent.Inventaire != versionInventaire {
		t.Fatalf("etat ecrit sous la regle %d, attendu %d", recent.Inventaire, versionInventaire)
	}
	if rejoues := recent.oublierPourInventaire(); rejoues != 0 {
		t.Errorf("un etat a jour serait rejoue a CHAQUE connexion (%d module(s))", rejoues)
	}
}

// --- les deux portes que l'inventaire aurait ouvertes ------------------------

// Un `.bashrc` remplacé par un lien vers un fichier que seul root lit. L'ancien
// code lisait à travers le lien et recopiait la cible dans un fichier
// appartenant à l'utilisateur : n'importe quel fichier du poste y passait.
func TestUnFichierDeDemarrageDevenuLienNEstNiLuNiRemplace(t *testing.T) {
	nom, home := compteDEssai(t)
	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte("root:$6$sel$hache:19000::::::\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	bashrc := filepath.Join(home, ".bashrc")
	if err := os.Symlink(secret, bashrc); err != nil {
		t.Fatalf("%v", err)
	}
	profile := filepath.Join(home, ".profile")
	if err := os.WriteFile(profile, []byte("# profile\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}

	politique := politiqueU(nom,
		moduleU(ModuleUserEnv, "env-editor", map[string]string{"name": "EDITOR", "value": "vi"}))
	_, rapport := appliquer(t, politique, nil)
	exigerApplique(t, rapport)

	if info, err := os.Lstat(bashrc); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf(".bashrc n'est plus le lien que l'utilisateur avait pose : %v", err)
	}
	if contenu, _ := os.ReadFile(secret); string(contenu) != "root:$6$sel$hache:19000::::::\n" {
		t.Errorf("la cible du lien a ete reecrite :\n%s", contenu)
	}
	// La fuite elle-même : le contenu de la cible, quelque part sous le HOME.
	_ = filepath.Walk(home, func(chemin string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if contenu, _ := os.ReadFile(chemin); strings.Contains(string(contenu), "$6$sel$hache") {
			t.Errorf("le contenu de la cible du lien a ete recopie dans %s", chemin)
		}
		return nil
	})
	// Le bloc est allé dans le fichier ordinaire.
	if contenu, _ := os.ReadFile(profile); !strings.Contains(string(contenu), vaultaireMarkerStart) {
		t.Errorf("le bloc n'a pas ete pose dans .profile :\n%s", contenu)
	}
}

// Même porte par `~/.ssh/config` : ici le module ÉCHOUE, et rien n'est écrit.
func TestUneConfigSSHDevenueLienFaitEchouerLeModule(t *testing.T) {
	nom, home := compteDEssai(t)
	secret := filepath.Join(t.TempDir(), "cle")
	if err := os.WriteFile(secret, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("%v", err)
	}
	config := filepath.Join(home, ".ssh", "config")
	if err := os.Symlink(secret, config); err != nil {
		t.Fatalf("%v", err)
	}

	_, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleUserSSHClientConfig, "ssh-bastion",
		map[string]string{"host_alias": "bastion", "hostname": "bastion.exemple.fr"})), nil)
	if rapport.Modules[0].Result != ResultFailed {
		t.Fatalf("resultat = %s, attendu un echec : %s", rapport.Modules[0].Result, rapport.Modules[0].Detail)
	}
	if info, err := os.Lstat(config); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Error("le lien a ete remplace")
	}
	if contenu, _ := os.ReadFile(secret); string(contenu) != "-----BEGIN PRIVATE KEY-----\n" {
		t.Errorf("la cible a ete reecrite :\n%s", contenu)
	}
}

// Le retrait. `os.Remove` résolvait les répertoires intermédiaires : avec un
// lien à la place de `~/.config`, une politique « retirer ~/.config/app.conf »
// faisait supprimer par root un fichier hors du dossier.
func TestUnRetraitNeTraversePasUnLien(t *testing.T) {
	nom, home := compteDEssai(t)
	ailleurs := t.TempDir()
	victime := filepath.Join(ailleurs, "app.conf")
	if err := os.WriteFile(victime, []byte("precieux\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.Symlink(ailleurs, filepath.Join(home, ".config")); err != nil {
		t.Fatalf("%v", err)
	}

	etat, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleFileDeploy, "menage",
		map[string]string{"path": "/%h/.config/app.conf", "state": "absent"})), nil)
	if rapport.Modules[0].Result != ResultFailed {
		t.Fatalf("resultat = %s, attendu un echec", rapport.Modules[0].Result)
	}
	if _, err := os.Stat(victime); err != nil {
		t.Fatalf("le fichier hors du HOME a ete supprime a travers le lien : %v", err)
	}
	if len(etat.Files) != 0 {
		t.Errorf("une absence jamais obtenue est inscrite : %v", cles(etat.Files))
	}
}

// Un lien à la place du fichier lui-même, en revanche, se retire : c'est le
// lien qui part, pas sa cible.
func TestUnLienALaPlaceDuFichierEstRetireEtPasSaCible(t *testing.T) {
	nom, home := compteDEssai(t)
	victime := filepath.Join(t.TempDir(), "cible")
	if err := os.WriteFile(victime, []byte("precieux\n"), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	lien := filepath.Join(home, "a-retirer")
	if err := os.Symlink(victime, lien); err != nil {
		t.Fatalf("%v", err)
	}
	_, rapport := appliquer(t, politiqueU(nom, moduleU(ModuleFileDeploy, "menage",
		map[string]string{"path": "/%h/a-retirer", "state": "absent"})), nil)
	exigerApplique(t, rapport)
	if _, err := os.Lstat(lien); !os.IsNotExist(err) {
		t.Errorf("le lien n'a pas ete retire : %v", err)
	}
	if _, err := os.Stat(victime); err != nil {
		t.Errorf("la cible du lien a ete supprimee : %v", err)
	}
}

// Un tube posé à la place d'un fichier relu. Ouvert sans précaution, il
// bloquerait l'agent jusqu'à ce qu'un écrivain se présente — c'est-à-dire la
// session PAM elle-même.
func TestUnTubeNeBloquePasLaLecture(t *testing.T) {
	_, home := compteDEssai(t)
	tube := filepath.Join(home, ".bashrc")
	if err := mkfifo(tube); err != nil {
		t.Skipf("mkfifo indisponible : %v", err)
	}
	fini := make(chan error, 1)
	go func() {
		_, _, err := lireFichierUtilisateur(home, tube, os.Getuid())
		fini <- err
	}()
	if err := <-fini; err == nil {
		t.Error("un tube a ete lu comme un fichier ordinaire")
	}
}

// Trop gros pour un fichier de démarrage : pas relu.
func TestUnFichierDemesureNEstPasRelu(t *testing.T) {
	_, home := compteDEssai(t)
	gros := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(gros, make([]byte, tailleMaxLecture+1), 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	if _, _, err := lireFichierUtilisateur(home, gros, os.Getuid()); err == nil {
		t.Error("un fichier de plus d'un megaoctet a ete relu")
	}
}

// --- le bloc -----------------------------------------------------------------

func TestExtraireBloc(t *testing.T) {
	debut, fin := vaultaireMarkerStart, vaultaireMarkerEnd
	cas := []struct {
		nom, contenu, corps string
		present             bool
	}{
		{"absent", "alias x=y\n", "", false},
		{"present", "a\n" + debut + "\nligne 1\nligne 2\n" + fin + "\nb\n", "ligne 1\nligne 2", true},
		{"ouvert sans fermeture", "a\n" + debut + "\nligne 1\n", "", false},
		{"balises indentees", "  " + debut + "  \nx\n\t" + fin + "\n", "x", true},
		{"fermeture seule", fin + "\nx\n", "", false},
	}
	for _, c := range cas {
		corps, present := extraireBloc(c.contenu, debut, fin)
		if corps != c.corps || present != c.present {
			t.Errorf("%s : (%q, %v), attendu (%q, %v)", c.nom, corps, present, c.corps, c.present)
		}
	}
}

// Une attente de bloc écrite par un agent plus récent, avec un bloc que
// celui-ci ne connaît pas : incertitude, pas écart — et donc rien de rejoué.
func TestUnBlocInconnuEstUneIncertitude(t *testing.T) {
	etat := &ScopeState{Checks: map[string]SystemCheck{
		"x": {Kind: CheckFileBlock, Target: "/home/a/.bashrc" + separateurBloc + "futur",
			Expect: "compte=a,sha256=00", StateKey: "m"},
	}}
	constat := scanFromState(etat, ScopeUser, "a")
	if len(constat.Items) != 1 || constat.Items[0].Kind != DriftUnverifiable {
		t.Fatalf("ecarts = %+v, attendu une incertitude", constat.Items)
	}
	if modules := constat.ModulesConcerned(); len(modules) != 0 {
		t.Errorf("modules a rejouer = %v : une incertitude ne fait rien rejouer", modules)
	}
}

// --- utilitaires -------------------------------------------------------------

func cles(m map[string]FileState) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clesAttentes(m map[string]SystemCheck) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mkfifo(chemin string) error { return syscall.Mkfifo(chemin, 0o600) }
