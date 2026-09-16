package localusermanagement

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Les appartenances de groupe posées par l'agent.
//
// # Ce que ces tests gardent
//
// Un seul défaut compte vraiment ici : que l'agent retire une appartenance qu'il
// n'a pas posée. `/etc/group` porte aussi ce que l'administrateur local, un
// paquet ou un installeur y ont mis. Aligner naïvement sur la liste du serveur
// effacerait tout cela — silencieusement, à la première connexion, et sur toutes
// les machines du parc à la fois.
//
// C'est pourquoi l'agent tient un fichier de ce qu'il a posé, et ne retire que
// cela. Ces tests éprouvent cette limite dans les deux sens : ce qui doit partir,
// et surtout ce qui doit rester.

// machineSimulee redirige les deux fichiers vers un répertoire temporaire.
func machineSimulee(t *testing.T, contenuGroup string) string {
	t.Helper()

	dir := t.TempDir()
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(group, []byte(contenuGroup), 0644); err != nil {
		t.Fatalf("écriture de group : %v", err)
	}

	ancienRep, ancienGrp := repertoireEtat, fichierGroupes
	repertoireEtat, fichierGroupes = dir, group
	t.Cleanup(func() { repertoireEtat, fichierGroupes = ancienRep, ancienGrp })

	return group
}

func membresDe(t *testing.T, chemin, groupe string) []string {
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
		if len(champs) < 4 || strings.TrimSpace(champs[3]) == "" {
			return nil
		}
		return strings.Split(champs[3], ",")
	}
	return nil
}

// TestLAgentNeRetirePasCeQuIlNaPasPose.
//
// LE test de ce fichier. Un utilisateur inscrit à la main dans `sudo` par
// l'administrateur local doit y rester, même si le serveur n'annonce pas ce
// groupe.
func TestLAgentNeRetirePasCeQuIlNaPasPose(t *testing.T) {
	group := machineSimulee(t, "sudo:x:27:alice\ndevs:x:5100:\n")

	// Le serveur n'annonce que « devs ». « sudo » n'a jamais été posé par
	// l'agent : il ne doit pas y toucher.
	if _, err := AppliquerGroupesUtilisateur("alice", []string{"devs"}); err != nil {
		t.Fatalf("%v", err)
	}

	if m := membresDe(t, group, "sudo"); len(m) != 1 || m[0] != "alice" {
		t.Errorf("membres de sudo = %v : l'agent a retiré une appartenance qu'il "+
			"n'avait pas posée", m)
	}
	if m := membresDe(t, group, "devs"); len(m) != 1 || m[0] != "alice" {
		t.Errorf("membres de devs = %v, attendu [alice]", m)
	}
}

// TestCeQueLAgentAPoseEstRetireQuandLeServeurNeLAnnoncePlus.
//
// L'autre moitié : sans cela, un utilisateur retiré d'un groupe côté annuaire
// garderait son appartenance locale, et les droits qui vont avec, jusqu'à ce que
// quelqu'un aille éditer /etc/group à la main.
func TestCeQueLAgentAPoseEstRetireQuandLeServeurNeLAnnoncePlus(t *testing.T) {
	group := machineSimulee(t, "devs:x:5100:\nprod:x:5101:\n")

	if _, err := AppliquerGroupesUtilisateur("alice", []string{"devs", "prod"}); err != nil {
		t.Fatalf("%v", err)
	}
	if m := membresDe(t, group, "prod"); len(m) != 1 {
		t.Fatalf("membres de prod = %v après pose, attendu [alice]", m)
	}

	// Le serveur ne l'annonce plus dans « prod ».
	if _, err := AppliquerGroupesUtilisateur("alice", []string{"devs"}); err != nil {
		t.Fatalf("%v", err)
	}

	if m := membresDe(t, group, "prod"); len(m) != 0 {
		t.Errorf("membres de prod = %v : l'appartenance retirée côté annuaire "+
			"subsiste sur la machine", m)
	}
	if m := membresDe(t, group, "devs"); len(m) != 1 {
		t.Errorf("membres de devs = %v : l'appartenance encore voulue a été retirée", m)
	}
}

// TestUnGroupeAbsentDeLaMachineEstIgnore.
//
// L'agent ne CRÉE aucun groupe : lui en faire créer un lui donnerait un GID tiré
// au hasard que le reste du parc ne partagerait pas. Voir la spécification
// « Synchronisation des groupes de la machine ».
func TestUnGroupeAbsentDeLaMachineEstIgnore(t *testing.T) {
	group := machineSimulee(t, "devs:x:5100:\n")

	poses, err := AppliquerGroupesUtilisateur("alice", []string{"devs", "inexistant"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(poses) != 1 || poses[0] != "devs" {
		t.Errorf("posés = %v, attendu [devs] — un groupe absent ne se crée pas", poses)
	}

	contenu, _ := os.ReadFile(group)
	if strings.Contains(string(contenu), "inexistant") {
		t.Error("le groupe inexistant a été créé dans /etc/group")
	}
}

// TestUnEtatIllisibleNeRetireRien.
//
// Retirer sans savoir ce qu'on a posé reviendrait à toucher aux appartenances de
// l'administrateur local — exactement ce que le fichier d'état existe pour
// éviter. Devant un état illisible, la réponse prudente est de ne rien retirer.
func TestUnEtatIllisibleNeRetireRien(t *testing.T) {
	group := machineSimulee(t, "sudo:x:27:alice\ndevs:x:5100:alice\n")

	// Un répertoire à la place du fichier d'état : la lecture échoue.
	if err := os.Mkdir(filepath.Join(repertoireEtat, "user_groups.map"), 0755); err != nil {
		t.Fatalf("préparation : %v", err)
	}

	if _, err := AppliquerGroupesUtilisateur("alice", []string{"sudo"}); err != nil {
		t.Fatalf("%v", err)
	}

	if m := membresDe(t, group, "devs"); len(m) != 1 {
		t.Errorf("membres de devs = %v : un retrait a eu lieu malgré un état illisible", m)
	}
}

// TestLesNomsDangereuxSontEcartes.
//
// `/etc/group` et le fichier d'état sont deux formats à séparateurs. Un nom de
// groupe contenant « : » ou « , » déplacerait toutes les colonnes suivantes — et
// un nom choisi par qui peut créer un groupe côté annuaire deviendrait une
// écriture arbitraire dans un fichier système.
func TestLesNomsDangereuxSontEcartes(t *testing.T) {
	group := machineSimulee(t, "devs:x:5100:\n")

	poses, err := AppliquerGroupesUtilisateur("alice", []string{
		"devs",
		"root:x:0:alice", // tenterait d'ajouter une ligne
		"devs,root",      // tenterait de s'inscrire ailleurs
		"avec espace",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(poses) != 1 || poses[0] != "devs" {
		t.Errorf("posés = %v, attendu [devs] seul", poses)
	}

	contenu, _ := os.ReadFile(group)
	if strings.Contains(string(contenu), "root") {
		t.Errorf("/etc/group contient « root » après application :\n%s", contenu)
	}
}

// TestLAppartenanceSeLitChampParChamp.
//
// Régression. L'inscription testait la présence des LETTRES du nom dans la
// ligne, pas l'appartenance. « bob » était donc tenu pour déjà membre du groupe
// « bobs », et de tout groupe comptant un « bobby » : l'inscription n'avait pas
// lieu, sans erreur, et le droit manquait sans trace.
//
// Le cas n'était pas théorique : chaque compte reçoit un groupe primaire de son
// propre nom, dont la ligne commence par ce nom.
func TestLAppartenanceSeLitChampParChamp(t *testing.T) {
	group := machineSimulee(t, "bobs:x:5100:\ndevs:x:5101:bobby\nbob:x:5102:\n")

	for _, g := range []string{"bobs", "devs", "bob"} {
		pose, err := addUserToGroupManual(g, "bob")
		if err != nil {
			t.Fatalf("groupe %s : %v", g, err)
		}
		if !pose {
			t.Fatalf("groupe %s déclaré absent alors qu'il existe", g)
		}
	}

	for _, g := range []string{"bobs", "devs", "bob"} {
		if !contient(membresDe(t, group, g), "bob") {
			t.Errorf("bob absent de %s : la ressemblance des noms a été prise pour "+
				"une appartenance (membres = %v)", g, membresDe(t, group, g))
		}
	}
	if m := membresDe(t, group, "devs"); len(m) != 2 {
		t.Errorf("membres de devs = %v : bobby a été perdu", m)
	}
}

// TestUneSecondeInscriptionNeDupliquePas : deux connexions de suite ne doivent
// pas laisser le nom deux fois dans la ligne.
func TestUneSecondeInscriptionNeDupliquePas(t *testing.T) {
	group := machineSimulee(t, "devs:x:5100:\n")

	for i := 0; i < 3; i++ {
		if _, err := AppliquerGroupesUtilisateur("alice", []string{"devs"}); err != nil {
			t.Fatalf("passage %d : %v", i, err)
		}
	}

	if m := membresDe(t, group, "devs"); len(m) != 1 {
		t.Errorf("membres de devs = %v après trois connexions, attendu [alice]", m)
	}
}

// TestLEtatSurvitAuxRelectures : ce qui a été posé est relu tel quel.
func TestLEtatSurvitAuxRelectures(t *testing.T) {
	machineSimulee(t, "devs:x:5100:\nprod:x:5101:\n")

	if _, err := AppliquerGroupesUtilisateur("alice", []string{"devs", "prod"}); err != nil {
		t.Fatalf("%v", err)
	}

	poses, err := ChargerGroupesPoses()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(poses["alice"]) != 2 {
		t.Errorf("état relu = %v, attendu deux groupes", poses["alice"])
	}
}

// TestDeuxUtilisateursNeSEffacentPas.
//
// Le fichier porte tous les comptes. Une écriture qui repartirait d'une lecture
// périmée effacerait les appartenances de l'autre — c'est ce que le verrou
// empêche, et ce test le constate au niveau du contenu.
func TestDeuxUtilisateursNeSEffacentPas(t *testing.T) {
	machineSimulee(t, "devs:x:5100:\n")

	if _, err := AppliquerGroupesUtilisateur("alice", []string{"devs"}); err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := AppliquerGroupesUtilisateur("bob", []string{"devs"}); err != nil {
		t.Fatalf("%v", err)
	}

	poses, _ := ChargerGroupesPoses()
	if len(poses) != 2 {
		t.Errorf("%d compte(s) dans l'état, attendu 2 : une écriture a effacé l'autre", len(poses))
	}
}
