package dbjournaux

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	_ "github.com/go-sql-driver/mysql"

	"vaultaire/core/logs"
)

// Le journal commun contre une VRAIE base.
//
// # Pourquoi ce test existe malgré les tests de règle
//
// Les autres tests éprouvent les requêtes comme du texte. Ce qu'ils ne voient
// pas : qu'une colonne refuse une valeur en mode SQL strict — et avec elle le
// lot entier —, que DATETIME(6) garde bien les microsecondes qui départagent
// deux cores, que l'heure relue est celle qui a été écrite.
//
// # Sauté sans base
//
// Il demande une base JETABLE, désignée par VAULTAIRE_TEST_DSN :
//
//	VAULTAIRE_TEST_DSN='vlt:vlt@tcp(127.0.0.1:3306)/vltest?parseTime=true' go test ./core/database/db_journaux/
//
// Il y crée la table et y écrit. Ne le pointez jamais sur une base en service :
// la purge qu'il éprouve supprime les lignes de plus d'un an.

func baseDeTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("VAULTAIRE_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULTAIRE_TEST_DSN absent : pas de base de test MariaDB")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := CreateTables(db); err != nil {
		t.Fatal(err)
	}
	// Deux fois : le démarrage d'un core sur une base existante.
	if err := CreateTables(db); err != nil {
		t.Fatalf("second CreateTables : %v — un core ne redémarrerait pas", err)
	}
	return db
}

// coreUnique isole les lignes de ce test de celles d'un test précédent.
func coreUnique(t *testing.T) string {
	return fmt.Sprintf("test-%s-%d", t.Name(), time.Now().UnixNano())
}

func TestEnBaseLAllerRetourEstFidele(t *testing.T) {
	db := baseDeTest(t)
	core := coreUnique(t)
	t0 := time.Date(2026, 9, 24, 10, 0, 0, 123456000, time.UTC)

	lot := []logs.LogEntry{
		{Timestamp: t0, Severity: logs.SeverityInformational, Level: "INFO",
			Hostname: core, Message: "alice a fait group.add_user sur username bob", UserID: "7"},
		{Timestamp: t0.Add(time.Microsecond), Severity: logs.SeverityError, Level: "ERROR",
			Code: logs.CodeDBQuery, Hostname: core, Message: strings.Repeat("é", tailleMessage)},
		{Timestamp: t0.Add(2 * time.Microsecond), Severity: logs.SeverityWarning,
			Level: strings.Repeat("W", 40), Code: strings.Repeat("C", 80), Hostname: core,
			Message: "valeurs trop longues", RequestID: strings.Repeat("r", 200)},
	}
	if err := InsererLot(db, lot); err != nil {
		t.Fatalf("lot refusé par la base : %v — ces lignes seraient perdues, "+
			"et les deux cents du même lot avec elles", err)
	}

	p, err := Lister(db, Filtre{SeveriteMax: -1, Core: core})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Lignes) != 3 {
		t.Fatalf("%d ligne(s) relue(s), attendu 3", len(p.Lignes))
	}
	if !p.Lignes[0].Timestamp.Equal(t0.Add(2*time.Microsecond)) ||
		!p.Lignes[2].Timestamp.Equal(t0) {
		t.Errorf("heures relues %s … %s : les microsecondes ou le fuseau ne font "+
			"pas l'aller-retour", p.Lignes[0].Timestamp, p.Lignes[2].Timestamp)
	}
	if p.Lignes[2].UserID != "7" || p.Lignes[2].Hostname != core {
		t.Errorf("métadonnées perdues : %+v", p.Lignes[2])
	}
	if m := p.Lignes[1].Message; !utf8.ValidString(m) || !strings.HasSuffix(m, marqueTroncature) {
		t.Errorf("message long mal tronqué (%d octets)", len(m))
	}
}

func TestEnBaseFiltresEtPages(t *testing.T) {
	db := baseDeTest(t)
	core := coreUnique(t)
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	var lot []logs.LogEntry
	for i, niveau := range []string{"INFO", "WARNING", "ERROR", "INFO", "CRITICAL"} {
		sev, _ := logs.SeveriteDe(niveau)
		code := ""
		if niveau == "ERROR" {
			code = logs.CodeDBConnection
		}
		lot = append(lot, logs.LogEntry{Timestamp: t0.Add(time.Duration(i) * time.Minute),
			Severity: sev, Level: niveau, Code: code, Hostname: core, Message: niveau})
	}
	if err := InsererLot(db, lot); err != nil {
		t.Fatal(err)
	}

	compter := func(f Filtre) int {
		t.Helper()
		f.Core = core
		p, err := Lister(db, f)
		if err != nil {
			t.Fatal(err)
		}
		return len(p.Lignes)
	}
	if n := compter(Filtre{SeveriteMax: logs.SeverityWarning}); n != 3 {
		t.Errorf("WARNING et plus grave : %d ligne(s), attendu 3", n)
	}
	if n := compter(Filtre{SeveriteMax: -1, Code: logs.CodeDBConnection}); n != 1 {
		t.Errorf("par code : %d ligne(s), attendu 1", n)
	}
	if n := compter(Filtre{SeveriteMax: -1, Depuis: t0.Add(time.Minute),
		Jusqua: t0.Add(3 * time.Minute)}); n != 2 {
		t.Errorf("période [1 min, 3 min[ : %d ligne(s), attendu 2", n)
	}

	p1, _ := Lister(db, Filtre{SeveriteMax: -1, Core: core, ParPage: 2})
	p3, _ := Lister(db, Filtre{SeveriteMax: -1, Core: core, ParPage: 2, Page: 3})
	if len(p1.Lignes) != 2 || !p1.Suivante || p1.Lignes[0].Message != "CRITICAL" {
		t.Errorf("page 1 = %+v", p1)
	}
	if len(p3.Lignes) != 1 || p3.Suivante || p3.Lignes[0].Message != "INFO" {
		t.Errorf("page 3 = %+v", p3)
	}

	cores, err := Cores(db)
	if err != nil {
		t.Fatal(err)
	}
	trouve := false
	for _, c := range cores {
		trouve = trouve || c == core
	}
	if !trouve {
		t.Errorf("core %q absent de la liste des cores du journal", core)
	}
}

func TestEnBaseLaPurgeNeTouchePasAuxLignesRecentes(t *testing.T) {
	db := baseDeTest(t)
	core := coreUnique(t)
	maintenant := time.Now().UTC()

	lot := []logs.LogEntry{
		{Timestamp: maintenant.Add(-400 * 24 * time.Hour), Severity: 6, Level: "INFO", Hostname: core, Message: "ancienne"},
		{Timestamp: maintenant.Add(-time.Hour), Severity: 6, Level: "INFO", Hostname: core, Message: "récente"},
	}
	if err := InsererLot(db, lot); err != nil {
		t.Fatal(err)
	}
	if _, err := Purger(db, 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	p, _ := Lister(db, Filtre{SeveriteMax: -1, Core: core})
	if len(p.Lignes) != 1 || p.Lignes[0].Message != "récente" {
		t.Fatalf("après purge : %+v", p.Lignes)
	}
}

func TestEnBaseLEcrivainAtteintLaTable(t *testing.T) {
	db := baseDeTest(t)
	core := coreUnique(t)

	e := NouvelEcrivain(func(lot []logs.LogEntry) error { return InsererLot(db, lot) })
	for i := 0; i < TailleLot+1; i++ {
		e.Recevoir(logs.LogEntry{Timestamp: time.Now(), Severity: 6, Level: "INFO",
			Hostname: core, Message: fmt.Sprint(i)})
	}
	e.viderFile(nil)
	if n := e.perdues.Load(); n != 0 {
		t.Fatalf("%d ligne(s) perdue(s) avec une base qui répond", n)
	}
	p, _ := Lister(db, Filtre{SeveriteMax: -1, Core: core, ParPage: ParPageMax})
	if len(p.Lignes) != TailleLot+1 {
		t.Fatalf("%d ligne(s) en base, attendu %d", len(p.Lignes), TailleLot+1)
	}
}
