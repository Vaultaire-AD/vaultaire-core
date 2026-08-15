package logs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// La rotation faite par le core lui-même.
//
// Le temps est déplacé plutôt qu'attendu : un test qui dormirait jusqu'au
// lendemain pour éprouver une rotation quotidienne ne serait jamais lancé.

func avecRotationControlee(t *testing.T) (dir string, horloge *time.Time) {
	t.Helper()
	dir = avecJournalTemporaire(t)

	h := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	horloge = &h

	ancienMaintenant := maintenantJournal
	ancienArchives := ArchivesConservees
	ancienTaille := TailleMaxJournal
	ancienCompression := CompresserArchives

	maintenantJournal = func() time.Time { return h }

	t.Cleanup(func() {
		maintenantJournal = ancienMaintenant
		ArchivesConservees = ancienArchives
		TailleMaxJournal = ancienTaille
		CompresserArchives = ancienCompression
	})
	return dir, horloge
}

// TestLeChangementDeJourFaitTourner.
//
// Le déclencheur est la date de modification du FICHIER, pas un minuteur : un
// core arrêté trois jours archive les lignes à leur date, pas à celle du
// redémarrage.
func TestLeChangementDeJourFaitTourner(t *testing.T) {
	dir, horloge := avecRotationControlee(t)
	CompresserArchives = false
	chemin := filepath.Join(dir, "SQL_Injection.log")

	WriteLog("SQL_Injection", "tentative du 14")
	if err := os.Chtimes(chemin, *horloge, *horloge); err != nil {
		t.Fatalf("chtimes : %v", err)
	}

	*horloge = horloge.AddDate(0, 0, 1)
	WriteLog("SQL_Injection", "tentative du 15")

	archive := chemin + ".2026-08-14"
	contenu, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("archive %s absente : %v", archive, err)
	}
	if !strings.Contains(string(contenu), "tentative du 14") {
		t.Error("l'archive ne contient pas la ligne de la veille")
	}

	courant, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("fichier courant absent : %v", err)
	}
	if strings.Contains(string(courant), "tentative du 14") {
		t.Error("la ligne de la veille est restée dans le fichier courant")
	}
}

// TestLesDeuxFamillesTournentIndependamment.
//
// Elles partagent un répertoire. Une purge dont le préfixe serait trop large
// supprimerait les archives de l'autre famille — et « date » écrit beaucoup
// moins que « SQL_Injection », donc ses archives sont justement celles qui
// couvrent la plus longue période.
func TestLesDeuxFamillesTournentIndependamment(t *testing.T) {
	dir, horloge := avecRotationControlee(t)
	CompresserArchives = false
	ArchivesConservees = 1

	cheminDate := filepath.Join(dir, "date.log")
	WriteLog("date", "une date refusée")
	if err := os.Chtimes(cheminDate, *horloge, *horloge); err != nil {
		t.Fatalf("chtimes : %v", err)
	}
	*horloge = horloge.AddDate(0, 0, 1)
	WriteLog("date", "une autre")

	archiveDate := cheminDate + ".2026-08-14"
	if _, err := os.Stat(archiveDate); err != nil {
		t.Fatalf("archive de « date » absente : %v", err)
	}

	// Plusieurs rotations de l'AUTRE famille, avec une rétention de 1.
	cheminSQL := filepath.Join(dir, "SQL_Injection.log")
	for i := 0; i < 4; i++ {
		WriteLog("SQL_Injection", "tentative")
		if err := os.Chtimes(cheminSQL, *horloge, *horloge); err != nil {
			t.Fatalf("chtimes : %v", err)
		}
		*horloge = horloge.AddDate(0, 0, 1)
	}
	WriteLog("SQL_Injection", "dernière")

	if _, err := os.Stat(archiveDate); err != nil {
		t.Errorf("la purge de SQL_Injection a emporté l'archive de date : %v", err)
	}
}

// TestLaTailleFaitTournerDansLaMemeJournee.
//
// Un scan qui déclenche l'assainissement des requêtes en rafale fait de
// SQL_Injection.log le fichier qui grossit le plus vite de la machine.
func TestLaTailleFaitTournerDansLaMemeJournee(t *testing.T) {
	dir, _ := avecRotationControlee(t)
	CompresserArchives = false
	TailleMaxJournal = 200
	chemin := filepath.Join(dir, "SQL_Injection.log")

	for i := 0; i < 40; i++ {
		WriteLog("SQL_Injection", strings.Repeat("x", 40))
	}

	archives, err := listerArchives(chemin)
	if err != nil {
		t.Fatalf("listage : %v", err)
	}
	if len(archives) == 0 {
		t.Fatal("aucune archive : la taille ne déclenche pas de rotation")
	}
}

// TestLaPolitiqueEstLaMemeDesDeuxCotes.
//
// # Pourquoi ce test lit un autre module
//
// Le core et le socle réseau sont des modules Go DISJOINTS : le core n'importe
// pas `duckynetworkclient`. La rotation existe donc en deux exemplaires, et
// aucune compilation ne peut les tenir liés.
//
// C'est exactement le cas où deux valeurs dérivent en silence : quelqu'un règle
// la rétention d'un côté, l'autre reste à trente, et le parc et le core ne
// gardent plus la même chose sans que rien ne le dise.
//
// La TAILLE n'est pas comparée : elle diffère volontairement — 50 Mo pour le
// core, 20 pour un poste, 100 pour un proxy.
func TestLaPolitiqueEstLaMemeDesDeuxCotes(t *testing.T) {
	const cheminSocle = "../../../ducky-network-sdk-service/duckynetwork/logs/rotation.go"

	source, err := os.ReadFile(cheminSocle)
	if err != nil {
		t.Skipf("socle réseau introuvable depuis ce répertoire (%v) — "+
			"test ignoré plutôt qu'en échec : il dépend de la disposition du dépôt", err)
	}

	valeurs := map[string]string{
		"ArchivesConservees": "30",
		"CompresserArchives": "true",
	}
	for nom, attendu := range valeurs {
		motif := regexp.MustCompile(nom + `\s*=\s*(\S+)`)
		m := motif.FindStringSubmatch(string(source))
		if m == nil {
			t.Errorf("%s introuvable dans le socle réseau", nom)
			continue
		}
		if m[1] != attendu {
			t.Errorf("%s vaut %s dans le socle et %s ici : les deux moitiés du "+
				"produit ne gardent plus la même chose", nom, m[1], attendu)
		}
	}

	// Et la valeur locale doit être celle qu'on vient de comparer.
	if ArchivesConservees != 30 {
		t.Errorf("ArchivesConservees = %d ici, 30 attendu", ArchivesConservees)
	}
	if !CompresserArchives {
		t.Error("CompresserArchives est faux ici")
	}
}
