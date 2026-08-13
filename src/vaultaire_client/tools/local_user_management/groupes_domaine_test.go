package localusermanagement

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Les groupes du domaine posés sur la machine.
//
// # Ce que ces tests gardent
//
// Trois choses, par ordre de gravité si elles cassaient :
//
//  1. qu'aucun groupe ne soit créé avec un GID hors de la plage réservée — un
//     numéro qui retomberait dans 0-60000 donnerait à ses membres les droits
//     d'un groupe système ou du groupe primaire d'un compte ;
//  2. que l'agent ne touche jamais un groupe qu'il n'a pas créé, y compris un
//     homonyme local, y compris pour le renuméroter ;
//  3. qu'un groupe disparu du domaine soit VIDÉ et non EFFACÉ — l'effacement
//     rendrait orphelins les fichiers qui en portent la marque.

func gidDansGroup(t *testing.T, chemin, groupe string) (int, bool) {
	t.Helper()
	contenu, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("lecture de group : %v", err)
	}
	for _, l := range strings.Split(string(contenu), "\n") {
		if !strings.HasPrefix(l, groupe+":") {
			continue
		}
		champs := strings.Split(l, ":")
		if len(champs) < 4 {
			t.Fatalf("ligne malformée pour %q : %q", groupe, l)
		}
		gid, err := strconv.Atoi(strings.TrimSpace(champs[2]))
		if err != nil {
			t.Fatalf("GID illisible pour %q : %q", groupe, champs[2])
		}
		return gid, true
	}
	return 0, false
}

// TestUnGroupeEstCreeAvecLeGIDDuServeur.
func TestUnGroupeEstCreeAvecLeGIDDuServeur(t *testing.T) {
	group := machineSimulee(t, "root:x:0:\n")

	res, err := SynchroniserGroupesDomaine([]GroupeDomaine{
		{Nom: "devs", IDGroup: 12},
		{Nom: "prod", IDGroup: 34},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(res.Crees) != 2 {
		t.Fatalf("créés = %v, attendu deux groupes", res.Crees)
	}

	for nom, id := range map[string]int{"devs": 12, "prod": 34} {
		gid, ok := gidDansGroup(t, group, nom)
		if !ok {
			t.Errorf("%s absent de /etc/group", nom)
			continue
		}
		if gid != BaseGIDDomaine+id {
			t.Errorf("%s : GID %d, attendu %d — le numéro doit venir du serveur, "+
				"sinon deux machines du même domaine divergent", nom, gid, BaseGIDDomaine+id)
		}
	}
}

// TestAucunGroupeNEstCreeHorsDeLaPlage.
//
// La garde la plus importante du fichier. Un GID qui retomberait dans 0-60000
// donnerait à ses membres les droits d'un groupe système, ou ceux du groupe
// primaire d'un compte du domaine — et rien, sous Unix, ne le signalerait.
func TestAucunGroupeNEstCreeHorsDeLaPlage(t *testing.T) {
	group := machineSimulee(t, "root:x:0:\n")

	res, err := SynchroniserGroupesDomaine([]GroupeDomaine{
		{Nom: "correct", IDGroup: 1},
		{Nom: "zero", IDGroup: 0},
		{Nom: "negatif", IDGroup: -5},
		{Nom: "enorme", IDGroup: IDGroupMax + 1},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(res.Crees) != 1 || res.Crees[0] != "correct" {
		t.Errorf("créés = %v, attendu [correct] seul", res.Crees)
	}

	contenu, _ := os.ReadFile(group)
	for _, interdit := range []string{"zero", "negatif", "enorme"} {
		if strings.Contains(string(contenu), interdit) {
			t.Errorf("le groupe %q a été créé malgré un identifiant hors borne :\n%s",
				interdit, contenu)
		}
	}
	if strings.Contains(string(contenu), "zero:x:0:") {
		t.Error("un groupe a reçu le GID 0, qui est root")
	}
}

// TestUnHomonymeLocalNEstJamaisRenumerote.
//
// Le GID est écrit dans les inodes de tous les fichiers qui en portent la
// marque. Le changer les donnerait d'un coup à un autre groupe — sur des données
// que personne n'a demandé à toucher.
func TestUnHomonymeLocalNEstJamaisRenumerote(t *testing.T) {
	group := machineSimulee(t, "devs:x:500:alice\n")

	res, err := SynchroniserGroupesDomaine([]GroupeDomaine{{Nom: "devs", IDGroup: 12}})
	if err != nil {
		t.Fatalf("%v", err)
	}

	gid, ok := gidDansGroup(t, group, "devs")
	if !ok {
		t.Fatal("devs a disparu de /etc/group")
	}
	if gid != 500 {
		t.Errorf("GID de devs = %d, attendu 500 : un groupe local a été renuméroté", gid)
	}
	if len(res.Ignores) != 1 || res.Ignores[0] != "devs" {
		t.Errorf("ignorés = %v, attendu [devs] — l'écart doit être signalé", res.Ignores)
	}

	// Et ses membres sont intacts.
	if m := membresDe(t, group, "devs"); len(m) != 1 || m[0] != "alice" {
		t.Errorf("membres de devs = %v : un groupe local a perdu ses membres", m)
	}
}

// TestUnGroupeDisparuEstVideEtNonEfface.
func TestUnGroupeDisparuEstVideEtNonEfface(t *testing.T) {
	group := machineSimulee(t, "root:x:0:\n")

	if _, err := SynchroniserGroupesDomaine([]GroupeDomaine{
		{Nom: "devs", IDGroup: 12},
		{Nom: "prod", IDGroup: 34},
	}); err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := AppliquerGroupesUtilisateur("alice", []string{"devs", "prod"}); err != nil {
		t.Fatalf("%v", err)
	}

	// « prod » disparaît du domaine.
	res, err := SynchroniserGroupesDomaine([]GroupeDomaine{{Nom: "devs", IDGroup: 12}})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(res.Vides) != 1 || res.Vides[0] != "prod" {
		t.Errorf("vidés = %v, attendu [prod]", res.Vides)
	}

	if _, existe := gidDansGroup(t, group, "prod"); !existe {
		t.Error("la ligne de prod a été EFFACÉE : les fichiers qui portent son GID " +
			"sont devenus orphelins, et rien n'explique plus le numéro")
	}
	if m := membresDe(t, group, "prod"); len(m) != 0 {
		t.Errorf("membres de prod = %v : les droits n'ont pas été coupés", m)
	}
	if m := membresDe(t, group, "devs"); len(m) != 1 {
		t.Errorf("membres de devs = %v : un groupe encore annoncé a été vidé", m)
	}
}

// TestLAgentNeVidePasUnGroupeQuIlNaPasCree.
//
// Le pendant, pour les groupes, du test qui garde les appartenances.
func TestLAgentNeVidePasUnGroupeQuIlNaPasCree(t *testing.T) {
	group := machineSimulee(t, "sudo:x:27:alice\ndevs:x:500:bob\n")

	// Le serveur n'annonce qu'un groupe neuf. Ni « sudo » ni « devs » n'ont été
	// créés par l'agent : il ne doit pas y toucher.
	if _, err := SynchroniserGroupesDomaine([]GroupeDomaine{{Nom: "prod", IDGroup: 34}}); err != nil {
		t.Fatalf("%v", err)
	}

	if m := membresDe(t, group, "sudo"); len(m) != 1 {
		t.Errorf("membres de sudo = %v : un groupe de l'administrateur local a été vidé", m)
	}
	if m := membresDe(t, group, "devs"); len(m) != 1 {
		t.Errorf("membres de devs = %v : un groupe local a été vidé", m)
	}
}

// TestUnEtatIllisibleNeVideRien.
func TestUnEtatIllisibleNeVideRien(t *testing.T) {
	group := machineSimulee(t, "root:x:0:\n")

	if _, err := SynchroniserGroupesDomaine([]GroupeDomaine{{Nom: "prod", IDGroup: 34}}); err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := AppliquerGroupesUtilisateur("alice", []string{"prod"}); err != nil {
		t.Fatalf("%v", err)
	}

	// Un répertoire à la place de la carte : la lecture échoue.
	if err := os.RemoveAll(groupsMapPath()); err != nil {
		t.Fatalf("préparation : %v", err)
	}
	if err := os.Mkdir(groupsMapPath(), 0755); err != nil {
		t.Fatalf("préparation : %v", err)
	}

	if _, err := SynchroniserGroupesDomaine(nil); err != nil {
		t.Fatalf("%v", err)
	}

	if m := membresDe(t, group, "prod"); len(m) != 1 {
		t.Errorf("membres de prod = %v : un vidage a eu lieu malgré un état illisible", m)
	}
}

// TestUnGIDDejaOccupeEstRefuse.
//
// Deux lignes de même numéro donnent aux membres de l'une les droits de l'autre,
// et rien ne le signale : `ls -l` affiche le premier nom trouvé.
func TestUnGIDDejaOccupeEstRefuse(t *testing.T) {
	group := machineSimulee(t, "autre:x:100012:\n")

	res, err := SynchroniserGroupesDomaine([]GroupeDomaine{{Nom: "devs", IDGroup: 12}})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(res.Crees) != 0 {
		t.Errorf("créés = %v : un GID déjà occupé a été réutilisé", res.Crees)
	}

	contenu, _ := os.ReadFile(group)
	if strings.Contains(string(contenu), "devs") {
		t.Errorf("devs a été créé sur un GID occupé :\n%s", contenu)
	}
}

// TestLaCarteRetrouveUnGroupeDejaEnPlace.
//
// Une machine dont la carte a été perdue — réinstallation, /etc/vaultaire effacé
// — doit reprendre la main sur ses groupes sans les recréer, et sans les
// abandonner définitivement. C'est la règle sans état qui le permet : le GID
// recalculé est le même.
func TestLaCarteRetrouveUnGroupeDejaEnPlace(t *testing.T) {
	machineSimulee(t, "devs:x:100012:alice\n")

	if _, err := SynchroniserGroupesDomaine([]GroupeDomaine{{Nom: "devs", IDGroup: 12}}); err != nil {
		t.Fatalf("%v", err)
	}

	crees, err := ChargerGroupesCrees()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if crees["devs"] != BaseGIDDomaine+12 {
		t.Errorf("carte = %v : un groupe déjà au bon GID doit être repris en gestion", crees)
	}
}

func TestAnalyserLigneGroupe(t *testing.T) {
	cas := []struct {
		quoi   string
		ligne  string
		nom    string
		id     int
		erreur bool
	}{
		{"ligne normale", "devs:12", "devs", 12, false},
		{"espaces autour", "  devs : 12  ", "devs", 12, false},
		{"séparateur absent", "devs", "", 0, true},
		{"nom vide", ":12", "", 0, true},
		{"identifiant vide", "devs:", "", 0, true},
		{"identifiant illisible", "devs:abc", "", 0, true},
		{"GID 0, qui est root", "devs:0", "", 0, true},
		{"identifiant négatif", "devs:-1", "", 0, true},
		{"au-delà de la borne", "devs:60001", "", 0, true},
		{"ligne /etc/group injectée", "root:x:0:alice", "", 0, true},
		{"virgule, séparateur de membres", "a,b:12", "", 0, true},
		{"ligne vide", "", "", 0, true},
	}

	for _, c := range cas {
		g, err := AnalyserLigneGroupe(c.ligne)
		if c.erreur {
			if err == nil {
				t.Errorf("%s : ligne %q acceptée → %+v", c.quoi, c.ligne, g)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s : %v", c.quoi, err)
			continue
		}
		if g.Nom != c.nom || g.IDGroup != c.id {
			t.Errorf("%s : %+v, attendu %s/%d", c.quoi, g, c.nom, c.id)
		}
	}
}

// TestUneLigneSansRetourFinalNeColleraPas.
//
// Un /etc/group qui ne finit pas par un saut de ligne — ce qui arrive après une
// écriture interrompue — ferait coller la nouvelle ligne à la précédente, et
// deux groupes n'en feraient plus qu'un, illisible.
func TestUneLigneSansRetourFinalNeColleraPas(t *testing.T) {
	group := machineSimulee(t, "root:x:0:") // sans « \n » final

	if _, err := SynchroniserGroupesDomaine([]GroupeDomaine{{Nom: "devs", IDGroup: 12}}); err != nil {
		t.Fatalf("%v", err)
	}

	contenu, _ := os.ReadFile(group)
	if strings.Contains(string(contenu), "root:x:0:devs") {
		t.Errorf("la ligne s'est collée à la précédente :\n%s", contenu)
	}
	if _, ok := gidDansGroup(t, group, "devs"); !ok {
		t.Errorf("devs illisible :\n%s", contenu)
	}
}

// --- purge ------------------------------------------------------------------

func TestLaPurgeNeProposeQueDesGroupesVides(t *testing.T) {
	machineSimulee(t, "root:x:0:\n")

	if _, err := SynchroniserGroupesDomaine([]GroupeDomaine{
		{Nom: "devs", IDGroup: 12},
		{Nom: "prod", IDGroup: 34},
	}); err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := AppliquerGroupesUtilisateur("alice", []string{"devs"}); err != nil {
		t.Fatalf("%v", err)
	}

	orphelins, err := GroupesOrphelins()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(orphelins) != 1 || orphelins[0].Nom != "prod" {
		t.Errorf("orphelins = %+v, attendu [prod] : un groupe peuplé ne doit pas "+
			"être proposé à l'effacement", orphelins)
	}
}

func TestLaPurgeRefuseUnGroupeNonCreeParVaultaire(t *testing.T) {
	machineSimulee(t, "sudo:x:27:\n")

	if _, err := EffacerGroupesVides([]string{"sudo"}); err == nil {
		t.Error("l'effacement de sudo a été accepté : un groupe que l'agent n'a " +
			"pas créé ne doit jamais être effacé, et le taire ferait croire le " +
			"geste fait")
	}
}

func TestLaPurgeEffaceCeQuElleAAnnonce(t *testing.T) {
	group := machineSimulee(t, "root:x:0:\n")

	if _, err := SynchroniserGroupesDomaine([]GroupeDomaine{{Nom: "prod", IDGroup: 34}}); err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := SynchroniserGroupesDomaine(nil); err != nil {
		t.Fatalf("%v", err)
	}

	effaces, err := PurgerGroupesOrphelins()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(effaces) != 1 || effaces[0] != "prod" {
		t.Fatalf("effacés = %v, attendu [prod]", effaces)
	}
	if _, existe := gidDansGroup(t, group, "prod"); existe {
		t.Error("prod figure encore dans /etc/group après purge")
	}

	crees, _ := ChargerGroupesCrees()
	if _, reste := crees["prod"]; reste {
		t.Error("prod figure encore dans la carte après purge")
	}
}

// TestLaCarteEstEcriteAtomiquement : aucun fichier temporaire ne subsiste.
func TestLaCarteEstEcriteAtomiquement(t *testing.T) {
	machineSimulee(t, "root:x:0:\n")

	if _, err := SynchroniserGroupesDomaine([]GroupeDomaine{{Nom: "devs", IDGroup: 12}}); err != nil {
		t.Fatalf("%v", err)
	}

	if _, err := os.Stat(groupsMapPath() + ".tmp"); err == nil {
		t.Error("le fichier temporaire subsiste : le renommage n'a pas eu lieu")
	}
	if _, err := os.Stat(filepath.Join(repertoireEtat, "groups.map")); err != nil {
		t.Errorf("carte absente : %v", err)
	}
}
