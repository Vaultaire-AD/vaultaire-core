package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vaultaire/core/storage"
)

// La rotation des deux journaux FICHIER du core.
//
// # Ce que ces tests gardent
//
// Le core écrit l'essentiel sur la sortie standard ; seules deux familles
// passent par un fichier — « date » et « SQL_Injection ». Peu de volume, donc
// peu d'attention, donc exactement le genre d'endroit où une régression passe
// des mois sans être vue.
//
// Le fichier est rouvert PAR SON CHEMIN à chaque ligne. C'est ce qui rend
// logrotate suffisant sans code de rotation : il renomme, la ligne suivante
// recrée. Un descripteur gardé ouvert ferait écrire dans l'archive, et le
// fichier courant resterait vide — sans erreur.

func avecJournalTemporaire(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	ancien := storage.LogPath
	storage.LogPath = dir + string(filepath.Separator)
	t.Cleanup(func() { storage.LogPath = ancien })

	return dir
}

// TestUneRotationEstSuivieSansRedemarrage rejoue ce que fait logrotate.
func TestUneRotationEstSuivieSansRedemarrage(t *testing.T) {
	dir := avecJournalTemporaire(t)
	chemin := filepath.Join(dir, "SQL_Injection.log")

	WriteLog("SQL_Injection", "avant la rotation")

	archive := chemin + ".1"
	if err := os.Rename(chemin, archive); err != nil {
		t.Fatalf("renommage : %v", err)
	}

	WriteLog("SQL_Injection", "apres la rotation")

	courant, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("le fichier courant n'a pas été recréé : %v\n"+
			"  Un descripteur est probablement gardé ouvert : le core écrirait "+
			"dans l'archive, et le fichier courant resterait vide.", err)
	}
	if !strings.Contains(string(courant), "apres la rotation") {
		t.Errorf("la ligne d'après rotation manque :\n%s", courant)
	}

	ancien, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("lecture de l'archive : %v", err)
	}
	if strings.Contains(string(ancien), "apres la rotation") {
		t.Error("une ligne écrite APRÈS la rotation a atterri dans l'archive")
	}
}

// TestLesJournauxFichierNeSontPasLisiblesParTous.
//
// « SQL_Injection.log » contient les identifiants refusés par l'assainissement,
// donc le texte de tentatives d'injection ; « date.log » des données d'état
// civil. Ils étaient créés en 0644, dans un répertoire en 0755.
func TestLesJournauxFichierNeSontPasLisiblesParTous(t *testing.T) {
	dir := avecJournalTemporaire(t)

	WriteLog("date", "une ligne")

	info, err := os.Stat(filepath.Join(dir, "date.log"))
	if err != nil {
		t.Fatalf("stat : %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("mode %#o : le journal est lisible hors de son propriétaire", mode)
	}
}

// TestUneFamilleFautiveNeCreePasDeFichier.
//
// `WriteLog` prend une FAMILLE, pas un niveau de journal. Un appel du dépôt
// passait « WARNING » et déposait un fichier de ce nom, qu'aucune rotation ne
// couvrait et que personne ne lisait. Et une famille contenant « / » ou « .. »
// écrirait hors du répertoire des journaux.
func TestUneFamilleFautiveNeCreePasDeFichier(t *testing.T) {
	dir := avecJournalTemporaire(t)

	for _, mauvaise := range []string{"", "  ", "../evasion", "a/b", strings.Repeat("x", 80)} {
		WriteLog(mauvaise, "contenu")
	}

	entrees, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("lecture du répertoire : %v", err)
	}
	if len(entrees) != 0 {
		var noms []string
		for _, e := range entrees {
			noms = append(noms, e.Name())
		}
		t.Errorf("fichiers créés depuis des familles refusées : %v", noms)
	}
}

// TestLesDeuxFamillesDuCoreSontAcceptees.
//
// Le contraire du précédent : la validation ne doit pas être si stricte qu'elle
// refuse ce que le code appelle réellement. Ces deux noms sont ceux des appels
// existants — les changer sans changer la validation rendrait le core muet sur
// ces deux chemins, en silence.
func TestLesDeuxFamillesDuCoreSontAcceptees(t *testing.T) {
	dir := avecJournalTemporaire(t)

	for _, famille := range []string{"date", "SQL_Injection"} {
		WriteLog(famille, "contenu")
		if _, err := os.Stat(filepath.Join(dir, famille+".log")); err != nil {
			t.Errorf("famille %q refusée alors qu'elle est appelée par le code : %v",
				famille, err)
		}
	}
}
