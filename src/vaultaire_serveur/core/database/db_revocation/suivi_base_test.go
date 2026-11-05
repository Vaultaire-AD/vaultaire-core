package dbrevocation

import (
	"testing"

	"vaultaire/core/revocation"
)

// Le suivi contre une VRAIE base — TO-DO 164. Sauté sans VAULTAIRE_TEST_DSN
// (voir rejeu_base_test.go).

func TestEnBaseLeSuiviRendChaqueCibleAvecSonEtat(t *testing.T) {
	db := baseDeTest(t)
	compte := nomUnique("u")
	a, b, c, d := nomUnique("pc-a"), nomUnique("pc-b"), nomUnique("pc-c"), nomUnique("pc-d")

	id, err := CreateOrder(db, compte, revocation.ModeSoft, revocation.ReasonCompromised, "admin", []string{a, b, c, d})
	if err != nil {
		t.Fatal(err)
	}
	// a : appliqué. b : remis deux fois, en échec. c : remis trois fois, muette.
	// d : jamais remis — hors ligne depuis l'ordre.
	if err := NoterEssai(db, a, []int{id}); err != nil {
		t.Fatal(err)
	}
	if err := MarkTarget(db, id, a, revocation.StatusAcked, string(revocation.ResultApplied)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := NoterEssai(db, b, []int{id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := MarkTarget(db, id, b, revocation.StatusFailed, "command_failed : 2 processus survivent"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := NoterEssai(db, c, []int{id}); err != nil {
			t.Fatal(err)
		}
	}

	suivi, err := SuiviPour(db, compte)
	if err != nil {
		t.Fatal(err)
	}
	if !suivi.Verrouille {
		t.Error("un compte sous verrouillage n'est pas rendu verrouillé")
	}
	if len(suivi.Ordres) != 1 || suivi.PlusAnciens != 0 {
		t.Fatalf("ordres rendus : %d, plus anciens : %d", len(suivi.Ordres), suivi.PlusAnciens)
	}
	o := suivi.Ordres[0]
	if o.ID != id || o.Total != 4 || o.Pending != 3 {
		t.Errorf("ordre %d : total %d, en attente %d — attendu %d, 4, 3", o.ID, o.Total, o.Pending, id)
	}
	if len(o.Cibles) != 4 {
		t.Fatalf("%d cible(s), attendu 4", len(o.Cibles))
	}

	// L'ordre : l'échec, la muette (la plus sollicitée), l'absente, l'appliquée.
	attendues := []struct {
		machine string
		statut  revocation.TargetStatus
		remises int
		echange bool
	}{
		{b, revocation.StatusFailed, 2, true},
		{c, revocation.StatusPending, 3, true},
		{d, revocation.StatusPending, 0, false},
		{a, revocation.StatusAcked, 1, true},
	}
	for i, att := range attendues {
		got := o.Cibles[i]
		if got.ComputeurID != att.machine || got.Status != att.statut || got.Attempts != att.remises {
			t.Errorf("rang %d : %s %s %d remise(s) — attendu %s %s %d",
				i, got.ComputeurID, got.Status, got.Attempts, att.machine, att.statut, att.remises)
		}
		// L'âge du dernier échange vient de la base : présent dès qu'il y en a
		// eu un, absent sinon — jamais inventé.
		if got.DepuisLeDernier.Valid != att.echange {
			t.Errorf("rang %d (%s) : dernier échange connu = %v, attendu %v", i, got.ComputeurID, got.DepuisLeDernier.Valid, att.echange)
		}
		if got.DepuisLeDernier.Valid && (got.DepuisLeDernier.Int64 < 0 || got.DepuisLeDernier.Int64 > 60) {
			t.Errorf("rang %d : dernier échange il y a %d s, pour une écriture faite à l'instant", i, got.DepuisLeDernier.Int64)
		}
	}
	if got := o.Cibles[2].Commentaire(); got != "jamais remis : machine hors ligne depuis l'ordre" {
		t.Errorf("la machine jamais jointe : %q", got)
	}

	// La levée : les cibles non appliquées passent à « levé », et le compte
	// n'est plus verrouillé. Deux ordres sont alors détaillés, le plus récent
	// d'abord.
	if _, err := LiftSoftRevocations(db, compte, "admin"); err != nil {
		t.Fatal(err)
	}
	levee, err := CreateOrder(db, compte, revocation.ModeUnlock, revocation.ReasonAdminRequest, "admin", []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	suivi, err = SuiviPour(db, compte)
	if err != nil {
		t.Fatal(err)
	}
	if suivi.Verrouille {
		t.Error("le compte est rendu verrouillé après la levée")
	}
	if len(suivi.Ordres) != 2 || suivi.Ordres[0].ID != levee || suivi.Ordres[1].ID != id {
		t.Fatalf("ordres après la levée : %+v — attendu la levée, puis le verrouillage", suivi.Ordres)
	}
	d2 := Compter(suivi.Ordres[1].Cibles)
	if d2.Levees != 3 || d2.Appliquees != 1 || d2.ResteAFaire() != 0 {
		t.Errorf("verrouillage levé : %+v — attendu 3 levées, 1 appliquée, rien à faire", d2)
	}
}

func TestEnBaseLeSuiviSeBorneAuxDerniersOrdres(t *testing.T) {
	db := baseDeTest(t)
	compte, pc := nomUnique("u"), nomUnique("pc")
	var dernier int
	for i := 0; i < MaxOrdresSuivis+3; i++ {
		id, err := CreateOrder(db, compte, revocation.ModeUnlock, revocation.ReasonAdminRequest, "admin", []string{pc})
		if err != nil {
			t.Fatal(err)
		}
		dernier = id
	}
	suivi, err := SuiviPour(db, compte)
	if err != nil {
		t.Fatal(err)
	}
	if len(suivi.Ordres) != MaxOrdresSuivis || suivi.PlusAnciens != 3 {
		t.Fatalf("%d ordre(s) détaillé(s), %d plus ancien(s) — attendu %d et 3", len(suivi.Ordres), suivi.PlusAnciens, MaxOrdresSuivis)
	}
	if suivi.Ordres[0].ID != dernier {
		t.Errorf("le premier ordre détaillé est le %d, attendu le plus récent (%d)", suivi.Ordres[0].ID, dernier)
	}
}

func TestEnBaseUnCompteSansOrdreRendUnSuiviVide(t *testing.T) {
	db := baseDeTest(t)
	suivi, err := SuiviPour(db, nomUnique("personne"))
	if err != nil {
		t.Fatal(err)
	}
	if len(suivi.Ordres) != 0 || suivi.Verrouille || suivi.PlusAnciens != 0 {
		t.Fatalf("suivi d'un compte sans ordre : %+v", suivi)
	}
}
