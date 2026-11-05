package dbgpo

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// La date d'une portée dont la politique ne change pas — TO-DO 166.
//
// Contre une VRAIE base, désignée par VAULTAIRE_TEST_DSN (voir
// db_journaux/base_test.go) : ce qui est éprouvé ici est qu'une requête touche
// la bonne ligne, et rien d'autre. Il n'y crée que les tables de conformité.

func baseConformite(t *testing.T) *sql.DB {
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
	for _, ddl := range complianceTablesDDL {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("création du schéma de conformité : %v", err)
		}
	}
	return db
}

func dateDe(t *testing.T, db *sql.DB, machine, scope, compte string) (rapport time.Time, derive sql.NullTime, ecarts int) {
	t.Helper()
	if err := db.QueryRow(`SELECT reported_at, drift_at, drift_count FROM gpo_compliance
		WHERE computeur_id = ? AND scope = ? AND target_user = ?`, machine, scope, compte).
		Scan(&rapport, &derive, &ecarts); err != nil {
		t.Fatal(err)
	}
	return rapport, derive, ecarts
}

func TestEnBaseUnePolitiqueInchangeeGardeLaMachineAJour(t *testing.T) {
	db := baseConformite(t)
	machine := fmt.Sprintf("pc%d", time.Now().UnixNano())
	const empreinte = "57f19f535b53dde195c5df9e8ed8701e0282f3a83af972b434cbcdb80302bd23"

	if err := SaveApplyReport(db, machine, "machine", "", empreinte, "applied", 3, nil); err != nil {
		t.Fatal(err)
	}
	if err := SaveApplyReport(db, machine, "user", "alice@acme.lan", empreinte, "applied", 3, nil); err != nil {
		t.Fatal(err)
	}
	if err := SaveDriftReport(db, machine, "machine", "", 7, []DriftEntry{{StateKey: "k", Kind: "modified", Path: "/etc/x"}}); err != nil {
		t.Fatal(err)
	}
	// La dernière application remonte à hier : la politique n'a pas bougé depuis.
	hier := time.Now().UTC().Add(-26 * time.Hour).Truncate(time.Second)
	if _, err := db.Exec(`UPDATE gpo_compliance SET reported_at = ?, drift_at = ? WHERE computeur_id = ?`,
		hier, hier, machine); err != nil {
		t.Fatal(err)
	}
	lire := func() ComplianceRow {
		rows, err := GetComplianceForClient(db, machine)
		if err != nil || len(rows) != 2 {
			t.Fatalf("lecture : %v, %d ligne(s)", err, len(rows))
		}
		return rows[0] // la portée machine, triée devant
	}
	maintenant := time.Now().UTC()
	if lire().Fraicheur(maintenant) != RapportEnRetard {
		t.Fatal("préparation : la portée devrait être en retard avant la confirmation")
	}

	// Une AUTRE empreinte : la ligne décrit une application que la machine dit
	// ne plus avoir. On ne la date pas.
	if err := ConfirmerEtat(db, machine, "machine", "", "0000"); err != nil {
		t.Fatal(err)
	}
	if lire().Fraicheur(maintenant) != RapportEnRetard {
		t.Fatal("une confirmation portant une autre empreinte a rafraîchi la ligne : " +
			"des colonnes d'une application antérieure passeraient pour actuelles")
	}

	if err := ConfirmerEtat(db, machine, "machine", "", empreinte); err != nil {
		t.Fatal(err)
	}
	if got := lire().Fraicheur(time.Now().UTC()); got != RapportAJour {
		t.Fatalf("après « rien à faire », la portée machine est %q : une machine dont la politique "+
			"ne change pas reste en retard pour toujours", got)
	}

	// Ni la dérive, ni la portée d'un compte ne bougent.
	_, derive, ecarts := dateDe(t, db, machine, "machine", "")
	if !derive.Valid || !derive.Time.Equal(hier) || ecarts != 1 {
		t.Errorf("colonnes de dérive modifiées (date %v, %d écart(s)) : elles appartiennent au scan", derive, ecarts)
	}
	if rapport, _, _ := dateDe(t, db, machine, "user", "alice@acme.lan"); !rapport.Equal(hier) {
		t.Errorf("la portée d'alice a été datée (%s) par la confirmation de la portée machine", rapport)
	}
}

// Une portée dont le dernier module est retiré n'a plus rien qui puisse
// dériver — TO-DO 86.
func TestEnBaseUnePorteeVideeNAffichePlusDeDerive(t *testing.T) {
	db := baseConformite(t)
	machine := fmt.Sprintf("pc%d", time.Now().UnixNano())

	un := []ModuleReport{{ModuleType: "file_deploy", StateKey: "file_deploy:/etc/x", Result: "applied"}}
	if err := SaveApplyReport(db, machine, "machine", "", "e1", "applied", 3, un); err != nil {
		t.Fatal(err)
	}
	if err := SaveDriftReport(db, machine, "machine", "", 1, []DriftEntry{{StateKey: "file_deploy:/etc/x", Kind: "modified", Path: "/etc/x"}}); err != nil {
		t.Fatal(err)
	}
	// Une AUTRE portée de la même machine, en écart elle aussi : elle ne doit
	// pas être touchée.
	if err := SaveApplyReport(db, machine, "user", "alice@acme.lan", "e2", "applied", 3, un); err != nil {
		t.Fatal(err)
	}
	if err := SaveDriftReport(db, machine, "user", "alice@acme.lan", 1, []DriftEntry{{StateKey: "k", Kind: "modified", Path: "/home/a/x"}}); err != nil {
		t.Fatal(err)
	}

	// Tant qu'il reste un module, une application ne touche PAS à la dérive :
	// elle effacerait un écart que rien n'a encore corrigé.
	if err := SaveApplyReport(db, machine, "machine", "", "e1b", "applied", 4, un); err != nil {
		t.Fatal(err)
	}
	if _, derive, ecarts := dateDe(t, db, machine, "machine", ""); !derive.Valid || ecarts != 1 {
		t.Fatalf("une application avec modules a effacé la dérive (%v, %d écart(s))", derive, ecarts)
	}

	// Le dernier module est retiré de la politique : l'agent applique zéro
	// module, et son scan n'aura plus jamais rien à dire.
	if err := SaveApplyReport(db, machine, "machine", "", "e0", "applied", 5, nil); err != nil {
		t.Fatal(err)
	}
	rows, err := GetComplianceForClient(db, machine)
	if err != nil || len(rows) != 2 {
		t.Fatalf("lecture : %v, %d ligne(s)", err, len(rows))
	}
	vide, alice := rows[0], rows[1]
	if vide.DriftAt.Valid || vide.DriftCount != 0 || vide.DriftChecked != 0 {
		t.Fatalf("portée vidée : dérive %v, %d écart(s), %d vérifié(s) — un écart sur un fichier que plus "+
			"aucune politique ne réclame resterait affiché pour toujours", vide.DriftAt, vide.DriftCount, vide.DriftChecked)
	}
	if got := vide.EtatConformite(); got != "rien à vérifier" {
		t.Errorf("libellé d'une portée sans module : %q", got)
	}
	if vide.NonVerifiee() {
		t.Error("une portée sans module compte comme « jamais vérifiée » dans le résumé")
	}
	if alice.DriftCount != 1 || !alice.DriftAt.Valid {
		t.Errorf("la portée d'alice a perdu son écart (%d, %v) avec celle de la machine", alice.DriftCount, alice.DriftAt)
	}
	ecarts, err := GetDriftForClient(db, machine)
	if err != nil || len(ecarts) != 1 || ecarts[0].Scope != "user" {
		t.Fatalf("écarts restants : %+v (%v) — attendu le seul écart d'alice", ecarts, err)
	}
}
