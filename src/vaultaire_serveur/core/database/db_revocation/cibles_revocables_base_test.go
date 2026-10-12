package dbrevocation

import (
	"testing"

	"vaultaire/core/revocation"
)

// TO-DO 167, contre une VRAIE base (VAULTAIRE_TEST_DSN, voir baseDeTest).

// idLogicielsDEssai crée, si besoin, la partie de id_logiciels que lisent les
// requêtes du 167, et y pose les machines données.
func idLogicielsDEssai(t *testing.T, machines map[string]string) {
	t.Helper()
	db := baseDeTest(t)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS id_logiciels (
		id_logiciel INT AUTO_INCREMENT PRIMARY KEY,
		logiciel_type VARCHAR(255) NOT NULL,
		computeur_id VARCHAR(255) NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for id, typ := range machines {
		if _, err := db.Exec(`INSERT INTO id_logiciels (logiciel_type, computeur_id) VALUES (?, ?)`, typ, id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnBaseLesServicesSontRangesEtWindowsAussi(t *testing.T) {
	db := baseDeTest(t)
	agent, proxy, windows := nomUnique("pc"), nomUnique("proxy"), nomUnique("win")
	idLogicielsDEssai(t, map[string]string{agent: "vaultaire_client", proxy: "vaultaire_proxy", windows: "vaultaire_client"})

	ordre1, err := CreateOrder(db, nomUnique("alice"), revocation.ModeSoft, revocation.ReasonCompromised, "admin",
		[]string{agent, proxy, windows})
	if err != nil {
		t.Fatal(err)
	}
	ordre2, err := CreateOrder(db, nomUnique("bob"), revocation.ModeSoft, revocation.ReasonCompromised, "admin",
		[]string{windows})
	if err != nil {
		t.Fatal(err)
	}

	// Les types se lisent, sans tenir compte de la casse de l'appel.
	types, err := TypesDesMachines(db, []string{agent, proxy, "absente"})
	if err != nil || types[agent] != "vaultaire_client" || types[proxy] != "vaultaire_proxy" || len(types) != 2 {
		t.Fatalf("TypesDesMachines = %v, %v", types, err)
	}

	// Le rangement de démarrage : le proxy seul.
	n, err := RangerLesCiblesSansCompte(db)
	if err != nil || n < 1 {
		t.Fatalf("RangerLesCiblesSansCompte = %d, %v", n, err)
	}
	if s, _ := statutDe(t, db, ordre1, proxy); s != string(revocation.StatusNonPrisEnCharge) {
		t.Errorf("proxy : %s, attendu unsupported", s)
	}
	if s, _ := statutDe(t, db, ordre1, agent); s != string(revocation.StatusPending) {
		t.Errorf("agent : %s, attendu pending — un agent n'est jamais rangé", s)
	}
	// Idempotent : un second démarrage ne range plus rien de ce parc.
	if s, _ := statutDe(t, db, ordre1, proxy); s == string(revocation.StatusPending) {
		t.Error("rangement non persistant")
	}

	// Windows répond « unsupported » sur UN ordre : tous les siens sont rangés.
	n, err = MarquerMachineNonPriseEnCharge(db, windows, "agent Windows V1 : révocation non appliquée")
	if err != nil || n != 2 {
		t.Fatalf("MarquerMachineNonPriseEnCharge = %d, %v (attendu 2 ordres)", n, err)
	}
	for _, o := range []int{ordre1, ordre2} {
		if s, _ := statutDe(t, db, o, windows); s != string(revocation.StatusNonPrisEnCharge) {
			t.Errorf("ordre %d sur Windows : %s", o, s)
		}
	}
	// Plus rien à remettre à Windows ni au proxy ; l'agent attend toujours.
	machines, err := MachinesEnAttente(db)
	if err != nil {
		t.Fatal(err)
	}
	vues := map[string]bool{}
	for _, m := range machines {
		vues[m] = true
	}
	if vues[windows] || vues[proxy] || !vues[agent] {
		t.Errorf("machines en attente : windows %v, proxy %v, agent %v", vues[windows], vues[proxy], vues[agent])
	}
}
