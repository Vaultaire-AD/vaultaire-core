package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// La propriété sur laquelle repose toute la rotation.
//
// # Ce que ces tests gardent
//
// Le fichier est rouvert PAR SON CHEMIN à chaque ligne. C'est ce qui permet à
// la rotation (voir rotation.go) de n'être qu'un renommage, sans aucune gestion
// de descripteur : elle renomme, et la ligne suivante recrée le fichier.
//
// Un programme qui garderait un descripteur ouvert continuerait d'écrire dans
// le fichier RENOMMÉ — donc dans l'archive — et le fichier courant resterait
// vide indéfiniment. Le symptôme est un journal qui s'arrête net après la
// première rotation, sans aucune erreur, et personne ne le remarque avant d'en
// avoir besoin.
//
// La propriété tient à une seule ligne de code et se détruirait en la
// déplaçant, pour économiser deux appels système. D'où ce test, qui la vérifie
// sur le comportement et non sur le texte : il RENOMME réellement le fichier et
// regarde où atterrit la ligne suivante.
//
// Elle vaut aussi pour un renommage VENU DE L'EXTÉRIEUR — un administrateur qui
// déplace le fichier, un outil de collecte. Rien ne casse, et la ligne suivante
// repart d'un fichier neuf.

// avecJournalTemporaire déplace le journal dans un répertoire jetable.
func avecJournalTemporaire(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// La variable d'environnement l'emporte sur storage.LogPath — c'est toute la
	// raison d'être de LogPathResolu. Si elle est posée sur la machine qui lance
	// les tests, ceux-ci écriraient dans le vrai répertoire des journaux et
	// échoueraient pour une raison introuvable.
	t.Setenv(storage.EnvLogPath, "")

	ancienChemin := storage.LogPath
	ancienNom := storage.NomJournal
	ancienSilence := storage.SilentConsole

	storage.LogPath = dir + string(filepath.Separator)
	storage.NomJournal = "test.log"
	// La sortie standard n'a rien à faire dans la sortie de test.
	storage.SilentConsole = true

	t.Cleanup(func() {
		storage.LogPath = ancienChemin
		storage.NomJournal = ancienNom
		storage.SilentConsole = ancienSilence
	})
	return filepath.Join(dir, "test.log")
}

// TestUnRenommageExterneEstSuiviSansRedemarrage.
//
// Un renommage venu de l'extérieur du programme. La ligne suivante doit
// atterrir dans un fichier NEUF, pas dans l'archive.
func TestUnRenommageExterneEstSuiviSansRedemarrage(t *testing.T) {
	chemin := avecJournalTemporaire(t)

	Write_log("INFO", "avant la rotation")

	// Le suffixe « .1 » ne ressemble à aucune archive datée : c'est bien un
	// geste extérieur qu'on éprouve, pas la rotation du paquet.
	archive := chemin + ".1"
	if err := os.Rename(chemin, archive); err != nil {
		t.Fatalf("renommage : %v", err)
	}

	Write_log("INFO", "apres la rotation")

	courant, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("le fichier courant n'a pas été recréé : %v\n"+
			"  Le programme garde probablement un descripteur ouvert : il écrit "+
			"dans l'archive, et le journal semble s'arrêter après la rotation.", err)
	}
	if !strings.Contains(string(courant), "apres la rotation") {
		t.Errorf("la ligne écrite après la rotation n'est pas dans le fichier courant :\n%s",
			courant)
	}
	if strings.Contains(string(courant), "avant la rotation") {
		t.Error("le fichier courant contient la ligne d'avant la rotation")
	}

	ancien, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("lecture de l'archive : %v", err)
	}
	if strings.Contains(string(ancien), "apres la rotation") {
		t.Error("une ligne écrite APRÈS la rotation a atterri dans l'archive : " +
			"le descripteur est resté ouvert, logrotate ne suffit plus")
	}
}

// TestLeRepertoireEstRecreeSIlDisparait.
//
// Cas voisin et réel : un nettoyage trop large, un tmpfs remonté. Sans
// recréation, l'agent perdrait son journal jusqu'au prochain redémarrage.
func TestLeRepertoireEstRecreeSIlDisparait(t *testing.T) {
	chemin := avecJournalTemporaire(t)

	Write_log("INFO", "première ligne")
	if err := os.RemoveAll(filepath.Dir(chemin)); err != nil {
		t.Fatalf("suppression du répertoire : %v", err)
	}

	Write_log("INFO", "après suppression du répertoire")

	contenu, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("le répertoire n'a pas été recréé : %v", err)
	}
	if !strings.Contains(string(contenu), "après suppression") {
		t.Error("la ligne n'a pas été écrite après recréation du répertoire")
	}
}

// TestLeJournalNEstPasLisibleParTous.
//
// Ce fichier nomme les comptes qui se connectent, ceux dont l'authentification
// est refusée, et les groupes du domaine posés sur la machine. Il était créé en
// 0644 : tout utilisateur du poste pouvait lire les tentatives des autres.
func TestLeJournalNEstPasLisibleParTous(t *testing.T) {
	chemin := avecJournalTemporaire(t)

	Write_log("INFO", "une ligne")

	info, err := os.Stat(chemin)
	if err != nil {
		t.Fatalf("stat : %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("mode %#o : le journal est lisible hors de son propriétaire", mode)
	}

	dir, err := os.Stat(filepath.Dir(chemin))
	if err != nil {
		t.Fatalf("stat du répertoire : %v", err)
	}
	// t.TempDir crée en 0700 ; on vérifie que l'écriture ne l'a pas élargi.
	if mode := dir.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("répertoire en %#o : élargi par la création du journal", mode)
	}
}

// TestLeNomDeJournalEstCeluiDuProgramme.
//
// Le socle est partagé entre l'agent et le proxy. Un nom écrit en dur ferait
// écrire au proxy dans le fichier de l'agent — donc pas de politique de
// rétention par entité, puisqu'il n'y aurait qu'un fichier pour deux.
func TestLeNomDeJournalEstCeluiDuProgramme(t *testing.T) {
	avecJournalTemporaire(t)

	storage.NomJournal = "vaultaire_proxy.log"
	Write_log("INFO", "ligne du proxy")

	attendu := filepath.Join(strings.TrimSuffix(storage.LogPath, string(filepath.Separator)),
		"vaultaire_proxy.log")
	if _, err := os.Stat(attendu); err != nil {
		t.Errorf("le journal n'a pas été écrit dans %s : %v", attendu, err)
	}
}

// TestUnNomDeJournalVideNeDesigneJamaisLeRepertoire.
//
// Un nom vide donnerait un chemin qui désigne le RÉPERTOIRE : l'ouverture
// échouerait à chaque ligne et le programme perdrait son journal en silence —
// puisque c'est le journal qui aurait dû le dire.
func TestUnNomDeJournalVideNeDesigneJamaisLeRepertoire(t *testing.T) {
	for _, vide := range []string{"", "   ", "\t"} {
		storage.NomJournal = vide
		if n := storage.NomJournalResolu(); strings.TrimSpace(n) == "" {
			t.Errorf("nom %q → %q : le chemin désignerait le répertoire", vide, n)
		}
	}
	// Un nom qui contient un répertoire est réduit à son dernier élément : sinon
	// une valeur mal posée écrirait hors du répertoire des journaux.
	storage.NomJournal = "../../etc/passwd"
	if n := storage.NomJournalResolu(); strings.Contains(n, "/") || strings.Contains(n, "..") {
		t.Errorf("nom %q : le journal sortirait de son répertoire", n)
	}
}

// TestUneFamilleFautiveNeCreePasDeFichier.
//
// `WriteLog` prend une FAMILLE d'événements, pas un niveau de journal. Deux
// appels du dépôt passaient « error » et « WARNING » : ils déposaient des
// fichiers de ce nom, qu'aucune rotation ne couvrait et que personne ne lisait.
//
// La validation ferme aussi la forme la plus grave : une famille contenant
// « / » ou « .. » écrirait hors du répertoire des journaux.
func TestUneFamilleFautiveNeCreePasDeFichier(t *testing.T) {
	dir := filepath.Dir(avecJournalTemporaire(t))

	for _, mauvaise := range []string{"", "   ", "../evasion", "a/b", "trop." + strings.Repeat("x", 80)} {
		WriteLog(mauvaise, "contenu")
	}

	entrees, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("lecture du répertoire : %v", err)
	}
	for _, e := range entrees {
		if e.Name() != "test.log" {
			t.Errorf("fichier inattendu créé : %q", e.Name())
		}
	}
}

// TestUneFamilleValideDonneUnFichierPointLog : le suffixe permet à la rotation
// de cibler un motif unique.
func TestUneFamilleValideDonneUnFichierPointLog(t *testing.T) {
	dir := filepath.Dir(avecJournalTemporaire(t))

	WriteLog("SQL_Injection", "tentative")

	if _, err := os.Stat(filepath.Join(dir, "SQL_Injection.log")); err != nil {
		t.Errorf("SQL_Injection.log absent : %v", err)
	}
}
