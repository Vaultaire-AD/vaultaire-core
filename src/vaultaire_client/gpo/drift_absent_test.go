package gpo

import (
	"os"
	"path/filepath"
	"testing"
)

// Les fichiers qui doivent être ABSENTS, et les attentes d'état système.
//
// Point 4 de la TO-DO, ses deux moitiés. La première ferme un trou de
// l'inventaire : un module dont l'effet est « ce fichier ne doit pas exister »
// ne laissait aucune trace, et le recréer ne produisait donc aucun écart. La
// seconde ferme le même trou pour ce qui n'est pas un fichier.

// TestUnFichierRecreeEstUneDerive.
//
// LE test de la première moitié. Une GPO retire
// /etc/modprobe.d/vaultaire-usb-storage.conf pour lever une interdiction, ou
// l'inverse — pose un fichier interdisant un module noyau. Quelqu'un le recrée,
// et la machine restait déclarée conforme indéfiniment.
func TestUnFichierRecreeEstUneDerive(t *testing.T) {
	dir := t.TempDir()
	revenu := filepath.Join(dir, "revenu.conf")
	parti := filepath.Join(dir, "parti.conf")

	// « revenu » a été recréé après que la politique l'a retiré.
	écrireFichier(t, revenu, "quelqu'un l'a remis\n", 0o644)

	état := &ScopeState{
		Modules: map[string]string{"interdiction": "fp"},
		Files: map[string]FileState{
			revenu: {Absent: true, StateKey: "interdiction"},
			parti:  {Absent: true, StateKey: "interdiction"},
		},
	}

	rapport := scanFromState(état, ScopeMachine, "")

	if rapport.Checked != 2 {
		t.Errorf("%d fichier(s) verifie(s), attendu 2", rapport.Checked)
	}
	if len(rapport.Items) != 1 {
		t.Fatalf("%d ecart(s), attendu 1 : %+v", len(rapport.Items), rapport.Items)
	}
	if rapport.Items[0].Path != revenu {
		t.Errorf("ecart sur %q, attendu %q", rapport.Items[0].Path, revenu)
	}
	if rapport.Items[0].Kind != DriftReappeared {
		t.Errorf("type %q, attendu %q — « disparu » et « reapparu » ne se lisent "+
			"pas de la meme facon", rapport.Items[0].Kind, DriftReappeared)
	}
	if rapport.Items[0].StateKey != "interdiction" {
		t.Errorf("StateKey %q : sans lui la correction ne sait pas quoi reappliquer",
			rapport.Items[0].StateKey)
	}
}

// TestUneAbsenceObtenueNEstPasUneDerive : le cas normal ne doit rien signaler.
func TestUneAbsenceObtenueNEstPasUneDerive(t *testing.T) {
	dir := t.TempDir()
	état := &ScopeState{
		Files: map[string]FileState{
			filepath.Join(dir, "jamais.conf"): {Absent: true, StateKey: "m"},
		},
	}
	if rapport := scanFromState(état, ScopeMachine, ""); !rapport.Conforming() {
		t.Errorf("ecart signale sur une absence obtenue : %+v", rapport.Items)
	}
}

// TestUneEntreeDAbsenceNEstPasComparee.
//
// Une entrée d'absence n'a ni hachage ni mode. Si le scan lui appliquait les
// contrôles des autres entrées, un fichier recréé produirait « contenu modifié »
// au lieu de « réapparu » — et un fichier bien absent produirait « disparu »,
// c'est-à-dire une dérive permanente sur le cas conforme.
func TestUneEntreeDAbsenceNEstPasComparee(t *testing.T) {
	dir := t.TempDir()
	chemin := filepath.Join(dir, "revenu.conf")
	écrireFichier(t, chemin, "n'importe quoi\n", 0o600)

	état := &ScopeState{
		Files: map[string]FileState{chemin: {Absent: true, StateKey: "m"}},
	}
	rapport := scanFromState(état, ScopeMachine, "")

	if len(rapport.Items) != 1 {
		t.Fatalf("%d ecart(s), attendu 1 : %+v", len(rapport.Items), rapport.Items)
	}
	if k := rapport.Items[0].Kind; k == DriftModified || k == DriftPermissions {
		t.Errorf("type %q : les contrôles de contenu et de mode ont ete appliques "+
			"a une entree d'absence", k)
	}
}

// TestUnEtatAncienNaPasDAbsences.
//
// Le champ Absent est ajouté. Un état écrit par une version antérieure ne le
// porte pas : il vaut « faux », donc l'ancien comportement, et aucun fichier ne
// doit brusquement être surveillé à l'envers.
func TestUnEtatAncienNaPasDAbsences(t *testing.T) {
	dir := t.TempDir()
	chemin := filepath.Join(dir, "existant.conf")
	écrireFichier(t, chemin, "contenu\n", 0o644)
	hash, _ := HashFile(chemin)

	état := &ScopeState{
		Files: map[string]FileState{chemin: {SHA256: hash, Mode: 0o644, StateKey: "m"}},
	}
	if rapport := scanFromState(état, ScopeMachine, ""); !rapport.Conforming() {
		t.Errorf("un etat sans le champ Absent produit des ecarts : %+v", rapport.Items)
	}
}

// --- l'entonnoir de suppression ---------------------------------------------

// TestRemoveSystemFileNoteLAbsence.
func TestRemoveSystemFileNoteLAbsence(t *testing.T) {
	ResetManifest()
	dir := t.TempDir()
	chemin := filepath.Join(dir, "a-retirer.conf")
	écrireFichier(t, chemin, "contenu\n", 0o644)

	existait, err := removeSystemFile(chemin)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !existait {
		t.Error("existait = faux alors que le fichier etait la")
	}
	if _, err := os.Stat(chemin); !os.IsNotExist(err) {
		t.Error("le fichier n'a pas ete retire")
	}

	inventaire := manifestSnapshot()
	entrée, connue := inventaire[chemin]
	if !connue {
		t.Fatal("la suppression n'a laisse aucune trace dans l'inventaire — " +
			"c'est exactement le trou que le point 4 ferme")
	}
	if !entrée.Absent {
		t.Error("l'entree n'est pas marquee absente")
	}
}

// TestUnFichierDejaAbsentEstNoteQuandMeme.
//
// Que quelqu'un ait devancé la politique ne change rien à ce qu'elle déclare :
// ce fichier ne doit pas exister, et le scan doit le surveiller.
func TestUnFichierDejaAbsentEstNoteQuandMeme(t *testing.T) {
	ResetManifest()
	chemin := filepath.Join(t.TempDir(), "jamais-la.conf")

	existait, err := removeSystemFile(chemin)
	if err != nil {
		t.Fatalf("un fichier absent ne doit pas produire d'erreur : %v", err)
	}
	if existait {
		t.Error("existait = vrai sur un fichier qui n'etait pas la")
	}
	if _, connue := manifestSnapshot()[chemin]; !connue {
		t.Error("une absence deja obtenue n'a pas ete notee")
	}
}

// TestUnEchecDeSuppressionNeNotePas.
//
// Un répertoire non vide ne se supprime pas. La politique n'a donc PAS abouti,
// et l'inscrire ferait surveiller une absence qui n'a jamais été obtenue — donc
// signaler une dérive éternelle sur un état qu'on n'a pas su atteindre.
func TestUnEchecDeSuppressionNeNotePas(t *testing.T) {
	ResetManifest()
	dir := t.TempDir()
	plein := filepath.Join(dir, "plein")
	écrireFichier(t, filepath.Join(plein, "dedans.txt"), "x\n", 0o644)

	if _, err := removeSystemFile(plein); err == nil {
		t.Fatal("la suppression d'un repertoire non vide a reussi")
	}
	if _, connue := manifestSnapshot()[plein]; connue {
		t.Error("une suppression en echec a ete notee comme une absence obtenue")
	}
}

// TestUneSuppressionEcraseUneEcriture.
//
// Les deux sens sont possibles dans un même cycle : un module peut retirer un
// fichier qu'un module antérieur avait déposé. C'est la dernière opération qui
// décrit l'état où le système a été laissé.
func TestUneSuppressionEcraseUneEcriture(t *testing.T) {
	ResetManifest()
	dir := t.TempDir()
	chemin := filepath.Join(dir, "pose-puis-retire.conf")

	if err := writeSystemFile(chemin, "contenu\n", 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := removeSystemFile(chemin); err != nil {
		t.Fatalf("%v", err)
	}

	entrée := manifestSnapshot()[chemin]
	if !entrée.Absent {
		t.Error("l'entree d'ecriture a survecu a la suppression : le scan " +
			"signalerait « disparu » sur un fichier que la politique retire")
	}
}

// TestLAttributionSuitLeChangementEtPasSeulementLaPresence.
//
// Régression du mécanisme d'attribution. La comparaison portait sur la seule
// présence du chemin : deux modules qui touchent au même fichier dans un cycle
// laissaient l'entrée attribuée au PREMIER, avec son hachage d'origine. Le scan
// signalait ensuite une dérive permanente et faisait réappliquer le mauvais
// module.
func TestLAttributionSuitLeChangementEtPasSeulementLaPresence(t *testing.T) {
	ResetManifest()
	dir := t.TempDir()
	chemin := filepath.Join(dir, "partage.conf")

	// Module A dépose.
	avantA := manifestSnapshot()
	if err := writeSystemFile(chemin, "version A\n", 0o644); err != nil {
		t.Fatalf("%v", err)
	}
	deA := manifestSince(avantA, "module-a")
	if _, ok := deA[chemin]; !ok {
		t.Fatal("le depot n'a pas ete attribue a A")
	}

	// Module B le retire.
	avantB := manifestSnapshot()
	if _, err := removeSystemFile(chemin); err != nil {
		t.Fatalf("%v", err)
	}
	deB := manifestSince(avantB, "module-b")

	entrée, ok := deB[chemin]
	if !ok {
		t.Fatal("le retrait n'a pas ete attribue a B : l'entree reste au compte " +
			"de A, avec son hachage d'origine")
	}
	if !entrée.Absent || entrée.StateKey != "module-b" {
		t.Errorf("entree = %+v, attendu absente et attribuee a module-b", entrée)
	}
}
