package logs

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// La rotation faite par le programme.
//
// Le temps est déplacé plutôt qu'attendu : un test qui dormirait jusqu'au
// lendemain pour éprouver une rotation quotidienne ne serait jamais lancé.

// avecRotationControlee installe une horloge et une politique pilotées par le
// test, et les restaure.
func avecRotationControlee(t *testing.T) (chemin string, horloge *time.Time) {
	t.Helper()
	chemin = avecJournalTemporaire(t)

	base := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	h := base
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
	return chemin, horloge
}

// ecrireAvecDate écrit une ligne et force la date de modification du fichier,
// puisque c'est elle qui décide du jour du contenu.
func ecrireAvecDate(t *testing.T, chemin, message string, quand time.Time) {
	t.Helper()
	Write_log("INFO", message)
	if err := os.Chtimes(chemin, quand, quand); err != nil {
		t.Fatalf("chtimes : %v", err)
	}
}

// TestLeChangementDeJourFaitTourner.
//
// LE test du lot. Le déclencheur est la date de modification du FICHIER, pas un
// minuteur : un programme arrêté trois jours doit archiver les lignes à leur
// date, pas à celle du redémarrage.
func TestLeChangementDeJourFaitTourner(t *testing.T) {
	chemin, horloge := avecRotationControlee(t)
	CompresserArchives = false

	ecrireAvecDate(t, chemin, "ligne du 14", *horloge)

	*horloge = horloge.AddDate(0, 0, 1)
	Write_log("INFO", "ligne du 15")

	archive := chemin + ".2026-08-14"
	contenuArchive, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("archive %s absente : %v", archive, err)
	}
	if !strings.Contains(string(contenuArchive), "ligne du 14") {
		t.Error("l'archive ne contient pas la ligne de la veille")
	}

	courant, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("fichier courant absent : %v", err)
	}
	if !strings.Contains(string(courant), "ligne du 15") {
		t.Error("le fichier courant ne contient pas la ligne du jour")
	}
	if strings.Contains(string(courant), "ligne du 14") {
		t.Error("la ligne de la veille est restée dans le fichier courant")
	}
}

// TestLArchivePorteLeJourDuContenuEtNonCeluiDeLArchivage.
//
// Un agent éteint trois jours reprend avec un fichier dont la dernière ligne
// date de trois jours. Nommer l'archive du jour du redémarrage ferait que les
// dates du nom ne correspondent plus aux dates des lignes, et chercher « la
// journée du 14 » deviendrait un exercice.
func TestLArchivePorteLeJourDuContenuEtNonCeluiDeLArchivage(t *testing.T) {
	chemin, horloge := avecRotationControlee(t)
	CompresserArchives = false

	ecrireAvecDate(t, chemin, "ligne du 14", *horloge)

	// Trois jours d'arrêt.
	*horloge = horloge.AddDate(0, 0, 3)
	Write_log("INFO", "au redémarrage")

	if _, err := os.Stat(chemin + ".2026-08-14"); err != nil {
		t.Errorf("archive attendue au 14 (jour du contenu) : %v", err)
	}
	if _, err := os.Stat(chemin + ".2026-08-17"); err == nil {
		t.Error("archive nommée au jour de l'archivage : les dates du nom ne " +
			"correspondraient plus aux dates des lignes")
	}
}

// TestLaTailleFaitTournerDansLaMemeJournee.
//
// Sans ce déclencheur, un emballement — une boucle d'authentification qui
// échoue — remplit la partition bien avant minuit.
func TestLaTailleFaitTournerDansLaMemeJournee(t *testing.T) {
	chemin, _ := avecRotationControlee(t)
	CompresserArchives = false
	TailleMaxJournal = 200

	for i := 0; i < 40; i++ {
		Write_log("INFO", strings.Repeat("x", 40))
	}

	archives, err := listerArchives(chemin)
	if err != nil {
		t.Fatalf("listage : %v", err)
	}
	if len(archives) == 0 {
		t.Fatal("aucune archive : la taille ne déclenche pas de rotation")
	}

	info, err := os.Stat(chemin)
	if err != nil {
		t.Fatalf("stat : %v", err)
	}
	if info.Size() >= TailleMaxJournal*2 {
		t.Errorf("le fichier courant fait %d octets pour un seuil de %d",
			info.Size(), TailleMaxJournal)
	}
}

// TestPlusieursRotationsLeMemeJourNeSEcrasentPas.
//
// Un emballement fait tourner plusieurs fois dans la journée. Sans suffixe
// numérique, la seconde archive écraserait la première — et on perdrait
// justement les lignes du début de l'incident, celles qui en disent la cause.
func TestPlusieursRotationsLeMemeJourNeSEcrasentPas(t *testing.T) {
	chemin, _ := avecRotationControlee(t)
	CompresserArchives = false
	TailleMaxJournal = 200

	for i := 0; i < 60; i++ {
		Write_log("INFO", strings.Repeat("y", 40))
	}

	archives, _ := listerArchives(chemin)
	if len(archives) < 2 {
		t.Fatalf("%d archive(s) : le suffixe numérique ne joue pas", len(archives))
	}
	vues := map[string]bool{}
	for _, a := range archives {
		if vues[a] {
			t.Errorf("archive en double : %s", a)
		}
		vues[a] = true
	}
}

// TestLesArchivesAuDelaDeLaRetentionSontSupprimees.
func TestLesArchivesAuDelaDeLaRetentionSontSupprimees(t *testing.T) {
	chemin, horloge := avecRotationControlee(t)
	CompresserArchives = false
	ArchivesConservees = 3

	for i := 0; i < 8; i++ {
		ecrireAvecDate(t, chemin, "jour", *horloge)
		*horloge = horloge.AddDate(0, 0, 1)
	}
	Write_log("INFO", "dernière")

	archives, err := listerArchives(chemin)
	if err != nil {
		t.Fatalf("listage : %v", err)
	}
	if len(archives) > ArchivesConservees {
		t.Errorf("%d archives conservées pour une rétention de %d : %v",
			len(archives), ArchivesConservees, archives)
	}
	if len(archives) == 0 {
		t.Fatal("toutes les archives ont été supprimées")
	}

	// Ce sont les PLUS RÉCENTES qui restent. Garder les plus anciennes
	// reviendrait à jeter ce qu'on vient d'écrire — l'inverse de ce qu'on veut
	// après un incident.
	if !strings.HasSuffix(archives[0], "2026-08-21") {
		t.Errorf("la plus récente conservée est %s, attendu celle du 21", archives[0])
	}
}

// TestLesArchivesSontCompresseesSaufLaPlusRecente.
//
// La plus récente est celle qu'on lit le lendemain d'un incident. Devoir la
// décompresser pour un grep ajoute un geste au pire moment.
func TestLesArchivesSontCompresseesSaufLaPlusRecente(t *testing.T) {
	chemin, horloge := avecRotationControlee(t)
	CompresserArchives = true

	for i := 0; i < 4; i++ {
		ecrireAvecDate(t, chemin, "contenu du jour", *horloge)
		*horloge = horloge.AddDate(0, 0, 1)
	}
	Write_log("INFO", "aujourd'hui")

	archives, err := listerArchives(chemin)
	if err != nil {
		t.Fatalf("listage : %v", err)
	}
	if len(archives) < 2 {
		t.Fatalf("%d archive(s), au moins 2 attendues", len(archives))
	}
	if strings.HasSuffix(archives[0], ".gz") {
		t.Error("la plus récente est compressée : elle doit rester lisible sans outil")
	}
	for _, a := range archives[1:] {
		if !strings.HasSuffix(a, ".gz") {
			t.Errorf("archive non compressée : %s", a)
		}
	}
}

// TestUneArchiveCompresseeResteLisible : le gzip n'est pas décoratif.
func TestUneArchiveCompresseeResteLisible(t *testing.T) {
	chemin, horloge := avecRotationControlee(t)
	CompresserArchives = true

	ecrireAvecDate(t, chemin, "message identifiable", *horloge)
	*horloge = horloge.AddDate(0, 0, 1)
	ecrireAvecDate(t, chemin, "lendemain", *horloge)
	*horloge = horloge.AddDate(0, 0, 1)
	Write_log("INFO", "surlendemain")

	gzChemin := chemin + ".2026-08-14.gz"
	f, err := os.Open(gzChemin)
	if err != nil {
		t.Fatalf("archive compressée absente : %v", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip illisible : %v", err)
	}
	contenu, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("lecture du gzip : %v", err)
	}
	if !strings.Contains(string(contenu), "message identifiable") {
		t.Errorf("le contenu ne survit pas à la compression :\n%s", contenu)
	}
	if _, err := os.Stat(chemin + ".2026-08-14"); err == nil {
		t.Error("l'original subsiste à côté du .gz : la place n'est pas récupérée")
	}
}

// TestUnFichierVideNeTournePas.
//
// Sinon 30 archives vides chassent les vraies au bout d'un mois de calme, et il
// ne reste rien à lire le jour où l'on cherche.
func TestUnFichierVideNeTournePas(t *testing.T) {
	chemin, horloge := avecRotationControlee(t)

	if err := os.WriteFile(chemin, nil, 0o600); err != nil {
		t.Fatalf("création : %v", err)
	}
	hier := horloge.AddDate(0, 0, -1)
	if err := os.Chtimes(chemin, hier, hier); err != nil {
		t.Fatalf("chtimes : %v", err)
	}

	Write_log("INFO", "première ligne réelle")

	archives, _ := listerArchives(chemin)
	if len(archives) != 0 {
		t.Errorf("un fichier vide a produit %d archive(s) : %v", len(archives), archives)
	}
}

// TestUneRetentionNulleNeSupprimeRien : la sortie volontaire.
func TestUneRetentionNulleNeSupprimeRien(t *testing.T) {
	chemin, horloge := avecRotationControlee(t)
	CompresserArchives = false
	ArchivesConservees = 0

	for i := 0; i < 5; i++ {
		ecrireAvecDate(t, chemin, "jour", *horloge)
		*horloge = horloge.AddDate(0, 0, 1)
	}
	Write_log("INFO", "dernière")

	archives, _ := listerArchives(chemin)
	if len(archives) < 5 {
		t.Errorf("%d archives : une rétention nulle doit tout conserver", len(archives))
	}
}

// TestLaRotationNeSupprimeQueLesArchivesDeCeJournal.
//
// Deux journaux cohabitent dans le même répertoire — l'agent et le proxy sur une
// machine de test, le core et ses deux familles. Un préfixe trop large ferait
// purger les archives du voisin.
func TestLaRotationNeSupprimeQueLesArchivesDeCeJournal(t *testing.T) {
	chemin, horloge := avecRotationControlee(t)
	CompresserArchives = false
	ArchivesConservees = 1

	dir := filepath.Dir(chemin)
	voisin := filepath.Join(dir, "autre.log.2026-08-01")
	if err := os.WriteFile(voisin, []byte("archive du voisin"), 0o600); err != nil {
		t.Fatalf("création du voisin : %v", err)
	}

	for i := 0; i < 4; i++ {
		ecrireAvecDate(t, chemin, "jour", *horloge)
		*horloge = horloge.AddDate(0, 0, 1)
	}
	Write_log("INFO", "dernière")

	if _, err := os.Stat(voisin); err != nil {
		t.Errorf("l'archive d'un autre journal a été supprimée : %v", err)
	}
}
