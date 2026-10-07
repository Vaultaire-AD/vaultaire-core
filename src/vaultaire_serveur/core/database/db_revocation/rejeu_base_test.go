package dbrevocation

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"vaultaire/core/revocation"
)

// Le rejeu contre une VRAIE base — TO-DO 49.
//
// Sauté sans base : il demande une base JETABLE, désignée par
// VAULTAIRE_TEST_DSN (voir db_journaux/base_test.go). Il y crée les deux tables
// de révocation et y écrit ; ne le pointez jamais sur une base en service.

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

func nomUnique(prefixe string) string {
	return fmt.Sprintf("%s%d", prefixe, time.Now().UnixNano())
}

func statutDe(t *testing.T, db *sql.DB, ordre int, machine string) (string, int) {
	t.Helper()
	var statut string
	var essais int
	if err := db.QueryRow(`SELECT status, attempts FROM user_revocation_target
		WHERE d_id_revocation = ? AND computeur_id = ?`, ordre, machine).Scan(&statut, &essais); err != nil {
		t.Fatal(err)
	}
	return statut, essais
}

// La colonne ajoutée par le 49 est rattrapée sur une table qui ne l'a pas.
func TestEnBaseLaColonneDesEssaisEstRattrapee(t *testing.T) {
	db := baseDeTest(t)
	if _, err := db.Exec(`ALTER TABLE user_revocation_target DROP COLUMN attempts`); err != nil {
		t.Fatal(err)
	}
	if err := CreateTables(db); err != nil {
		t.Fatalf("CreateTables sur une table d'avant le 49 : %v", err)
	}
	if _, err := db.Exec(`SELECT attempts FROM user_revocation_target LIMIT 1`); err != nil {
		t.Fatalf("colonne absente après le démarrage : %v — le rejeu échouerait à chaque tour", err)
	}
}

func TestEnBaseUnEssaiSeCompteEtEspace(t *testing.T) {
	db := baseDeTest(t)
	compte, pc := nomUnique("u"), nomUnique("pc")
	id, err := CreateOrder(db, compte, revocation.ModeSoft, revocation.ReasonCompromised, "admin", []string{pc})
	if err != nil {
		t.Fatal(err)
	}

	machines, err := MachinesEnAttente(db)
	if err != nil {
		t.Fatal(err)
	}
	trouvee := false
	for _, m := range machines {
		trouvee = trouvee || m == pc
	}
	if !trouvee {
		t.Fatalf("%s absente des machines en attente : son ordre ne serait jamais rejoué", pc)
	}

	avant, err := EnAttentePour(db, pc, 0)
	if err != nil || len(avant) != 1 {
		t.Fatalf("avant tout essai : %v, %v", avant, err)
	}
	if avant[0].Essais != 0 || avant[0].DepuisLeDernier.Valid {
		t.Fatalf("ordre neuf : %d essai(s), date %v — attendu zéro et sans date", avant[0].Essais, avant[0].DepuisLeDernier)
	}

	if err := NoterEssai(db, pc, []int{id}); err != nil {
		t.Fatal(err)
	}
	if err := NoterEssai(db, pc, []int{id}); err != nil {
		t.Fatal(err)
	}
	apres, err := EnAttentePour(db, pc, 0)
	if err != nil || len(apres) != 1 {
		t.Fatalf("après deux essais : %v, %v", apres, err)
	}
	if apres[0].Essais != 2 || !apres[0].DepuisLeDernier.Valid || apres[0].DepuisLeDernier.Int64 > 5 {
		t.Fatalf("après deux essais : %d essai(s), %v s — attendu 2 et quelques secondes au plus",
			apres[0].Essais, apres[0].DepuisLeDernier)
	}
	if statut, _ := statutDe(t, db, id, pc); statut != string(revocation.StatusPending) {
		t.Fatalf("statut %q après un essai : remettre n'est pas appliquer", statut)
	}

	// Acquitté : plus rien à rejouer, et un essai tardif ne le modifie plus.
	if err := MarkTarget(db, id, pc, revocation.StatusAcked, "applied"); err != nil {
		t.Fatal(err)
	}
	if err := NoterEssai(db, pc, []int{id}); err != nil {
		t.Fatal(err)
	}
	if reste, _ := EnAttentePour(db, pc, 0); len(reste) != 0 {
		t.Fatalf("un ordre acquitté est encore à rejouer : %v", reste)
	}
	if _, essais := statutDe(t, db, id, pc); essais != 2 {
		t.Fatalf("%d essais après acquittement, attendu 2 : un essai a été compté sur une cible close", essais)
	}
}

// Le défaut que le rejeu aurait aggravé : un verrouillage levé, jamais acquitté
// par une machine, lui était encore remis.
func TestEnBaseUnVerrouillageLeveNEstPlusRemis(t *testing.T) {
	db := baseDeTest(t)
	compte := nomUnique("u")
	acquittee, enEchec := nomUnique("pcA"), nomUnique("pcB")

	verrou, err := CreateOrder(db, compte, revocation.ModeSoft, revocation.ReasonCompromised, "admin",
		[]string{acquittee, enEchec})
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkTarget(db, verrou, acquittee, revocation.StatusAcked, "applied"); err != nil {
		t.Fatal(err)
	}
	// Sur l'autre, le compte est verrouillé mais des processus ont survécu.
	if err := MarkTarget(db, verrou, enEchec, revocation.StatusFailed, "command_failed : 2 processus restants"); err != nil {
		t.Fatal(err)
	}

	if n, err := LiftSoftRevocations(db, compte, "admin"); err != nil || n != 1 {
		t.Fatalf("levée : %d, %v", n, err)
	}
	levee, err := CreateOrder(db, compte, revocation.ModeUnlock, revocation.ReasonCompromised, "admin",
		[]string{acquittee, enEchec})
	if err != nil {
		t.Fatal(err)
	}

	// La machine en échec ne doit plus recevoir que la LEVÉE.
	ordres, err := PendingOrdersForClient(db, enEchec, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ordres) != 1 || ordres[0].ID != levee {
		t.Fatalf("ordres remis à la machine en échec : %+v — attendu la seule levée (%d). "+
			"Le verrouillage levé, rejoué, referme un compte que l'annuaire dit rétabli", ordres, levee)
	}
	if statut, _ := statutDe(t, db, verrou, enEchec); statut != string(revocation.StatusLifted) {
		t.Fatalf("cible du verrouillage levé : %q, attendu %q", statut, revocation.StatusLifted)
	}
	// Celle qui avait acquitté garde sa trace.
	if statut, _ := statutDe(t, db, verrou, acquittee); statut != string(revocation.StatusAcked) {
		t.Fatalf("cible acquittée devenue %q : la levée a effacé ce qui avait été fait", statut)
	}

	// Un compte rendu d'échec en retard ne la ranime pas…
	if err := MarkTarget(db, verrou, enEchec, revocation.StatusFailed, "command_failed : en retard"); err != nil {
		t.Fatal(err)
	}
	if statut, _ := statutDe(t, db, verrou, enEchec); statut != string(revocation.StatusLifted) {
		t.Fatalf("un échec tardif a remis la cible levée à %q : elle sera rejouée", statut)
	}
	// … mais un acquittement s'inscrit : il dit ce qui a été fait.
	if err := MarkTarget(db, verrou, enEchec, revocation.StatusAcked, "applied"); err != nil {
		t.Fatal(err)
	}
	if statut, _ := statutDe(t, db, verrou, enEchec); statut != string(revocation.StatusAcked) {
		t.Fatalf("acquittement tardif non inscrit : %q", statut)
	}

	// L'historique ne compte plus le verrouillage levé comme « en attente ».
	historique, err := HistoryFor(db, compte)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range historique {
		if r.ID == verrou && r.Pending != 0 {
			t.Fatalf("le verrouillage levé affiche %d machine(s) restant à traiter", r.Pending)
		}
		if r.ID == levee && r.Pending != 2 {
			t.Fatalf("la levée affiche %d machine(s) restant à traiter, attendu 2", r.Pending)
		}
	}
}

// Un verrouillage EN VIGUEUR, lui, reste rejoué — la levée ne range que ce
// qu'elle lève.
func TestEnBaseUnVerrouillageEnVigueurResteRejoue(t *testing.T) {
	db := baseDeTest(t)
	leve, garde, pc := nomUnique("u"), nomUnique("v"), nomUnique("pc")

	aLever, err := CreateOrder(db, leve, revocation.ModeSoft, revocation.ReasonOffboarding, "admin", []string{pc})
	if err != nil {
		t.Fatal(err)
	}
	enVigueur, err := CreateOrder(db, garde, revocation.ModeSoft, revocation.ReasonCompromised, "admin", []string{pc})
	if err != nil {
		t.Fatal(err)
	}
	suppression, err := CreateOrder(db, leve, revocation.ModeHard, revocation.ReasonOffboarding, "admin", []string{pc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LiftSoftRevocations(db, leve, "admin"); err != nil {
		t.Fatal(err)
	}

	ordres, err := EnAttentePour(db, pc, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int
	for _, o := range ordres {
		ids = append(ids, o.Ordre.ID)
	}
	if len(ids) != 2 || ids[0] != enVigueur || ids[1] != suppression {
		t.Fatalf("à rejouer : %v — attendu [%d %d] : le verrouillage d'un AUTRE compte et la suppression restent, "+
			"seul le verrouillage levé (%d) sort", ids, enVigueur, suppression, aLever)
	}
}

// Les machines sous verrou : celles que la levée doit atteindre, quels que
// soient les groupes d'aujourd'hui.
func TestEnBaseLesMachinesSousVerrouSontCellesDuVerrouillage(t *testing.T) {
	db := baseDeTest(t)
	compte, autre := nomUnique("u"), nomUnique("v")
	a, b, c := nomUnique("pcA"), nomUnique("pcB"), nomUnique("pcC")

	verrou, err := CreateOrder(db, compte, revocation.ModeSoft, revocation.ReasonOffboarding, "admin", []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkTarget(db, verrou, a, revocation.StatusAcked, "applied"); err != nil {
		t.Fatal(err)
	}
	// Une suppression et le verrouillage d'un AUTRE compte ne comptent pas.
	if _, err := CreateOrder(db, compte, revocation.ModeHard, revocation.ReasonOffboarding, "admin", []string{c}); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateOrder(db, autre, revocation.ModeSoft, revocation.ReasonOffboarding, "admin", []string{c}); err != nil {
		t.Fatal(err)
	}

	machines, err := MachinesSousVerrou(db, compte)
	if err != nil {
		t.Fatal(err)
	}
	if len(machines) != 2 || machines[0] != a || machines[1] != b {
		t.Fatalf("machines sous verrou : %v — attendu %s et %s : acquittée ou non, une machine visée a pu verrouiller",
			machines, a, b)
	}

	if _, err := LiftSoftRevocations(db, compte, "admin"); err != nil {
		t.Fatal(err)
	}
	if apres, _ := MachinesSousVerrou(db, compte); len(apres) != 0 {
		t.Fatalf("après la levée : %v — plus aucun verrouillage n'est en vigueur", apres)
	}
}
