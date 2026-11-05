package dbgpo

import (
	"fmt"
	"testing"
	"time"
)

// TO-DO 172 : les demandes de cycle relayées, contre une VRAIE base
// (VAULTAIRE_TEST_DSN). Ce qui compte : une demande n'est prise qu'une fois, et
// une demande périmée n'est plus relevée.

func TestEnBaseUneDemandeNEstPriseQuUneFois(t *testing.T) {
	db := baseConformite(t)
	if _, err := db.Exec(tableDemandesCycleDDL); err != nil {
		t.Fatal(err)
	}
	machine := fmt.Sprint("PC-", time.Now().UnixNano())
	id, err := EcrireDemandeDeCycle(db, machine, "GPO base", "core1")
	if err != nil || id == 0 {
		t.Fatalf("écriture : %d %v", id, err)
	}

	enAttente, err := DemandesDeCycleEnAttente(db)
	if err != nil {
		t.Fatal(err)
	}
	trouvee := false
	for _, d := range enAttente {
		if d.ID == id {
			trouvee = d.ComputeurID == machine && d.Motif == "GPO base" && d.DemandePar == "core1"
		}
	}
	if !trouvee {
		t.Fatalf("la demande %d n'est pas en attente telle qu'écrite : %+v", id, enAttente)
	}

	// Deux cores la prennent en même temps : un seul y parvient.
	resultats := make(chan bool, 2)
	for _, c := range []string{"core2", "core3"} {
		go func(c string) {
			ok, _ := PrendreDemandeDeCycle(db, id, c)
			resultats <- ok
		}(c)
	}
	n := 0
	for i := 0; i < 2; i++ {
		if <-resultats {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d core(s) ont pris la demande, attendu 1", n)
	}
	if err := NoterRemise(db, id, true); err != nil {
		t.Fatal(err)
	}

	issues, err := IssuesDesDemandes(db, []int64{id, -1})
	if err != nil {
		t.Fatal(err)
	}
	if i := issues[id]; !i.Prise || !i.Remise || (i.PrisePar != "core2" && i.PrisePar != "core3") {
		t.Errorf("issue %+v", i)
	}
	if _, vu := issues[-1]; vu {
		t.Error("une demande inexistante a une issue")
	}

	// Prise : elle n'est plus en attente.
	enAttente, _ = DemandesDeCycleEnAttente(db)
	for _, d := range enAttente {
		if d.ID == id {
			t.Error("une demande prise est encore en attente")
		}
	}
}

func TestEnBaseUneDemandePerimeeNEstPlusRelevee(t *testing.T) {
	db := baseConformite(t)
	if _, err := db.Exec(tableDemandesCycleDDL); err != nil {
		t.Fatal(err)
	}
	machine := fmt.Sprint("PC-vieux-", time.Now().UnixNano())
	id, err := EcrireDemandeDeCycle(db, machine, "", "core1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE gpo_cycle_demande SET cree_le = NOW(3) - INTERVAL 2 HOUR WHERE id_demande = ?`, id); err != nil {
		t.Fatal(err)
	}
	enAttente, _ := DemandesDeCycleEnAttente(db)
	for _, d := range enAttente {
		if d.ID == id {
			t.Error("une demande de deux heures est encore relevée")
		}
	}
	if n, err := OublierDemandesDeCycle(db); err != nil || n < 1 {
		t.Errorf("oubli : %d, %v", n, err)
	}
}
