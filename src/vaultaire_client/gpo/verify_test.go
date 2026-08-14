package gpo

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Le socle de vérification des effets NON-fichier.
//
// Ces tests éprouvent le PARCOURS — attribution, tri, distinction entre « l'état
// est mauvais » et « je n'ai pas pu savoir » — avec des vérificateurs simulés.
// Les vrais lancent des commandes système : les faire tourner ici rendrait le
// test dépendant de la machine, donc soit ignoré, soit faux.
//
// Ce que les vrais vérificateurs ont, en revanche, c'est un test de leur
// ANALYSE : voir verifiers_test.go.

// avecChecker installe un vérificateur le temps d'un test.
func avecChecker(t *testing.T, kind string, c Checker) {
	t.Helper()
	ancien, existait := checkers[kind]
	checkers[kind] = c
	t.Cleanup(func() {
		if existait {
			checkers[kind] = ancien
			return
		}
		delete(checkers, kind)
	})
}

// TestUnEtatSystemeDeriveEstSignale.
//
// LE test de la seconde moitié du point 4. Un service réactivé, une table
// nftables vidée, un compte remis dans sudo : invisibles, et la machine était
// déclarée conforme.
func TestUnEtatSystemeDeriveEstSignale(t *testing.T) {
	avecChecker(t, "essai", func(c SystemCheck) (bool, string, error) {
		if c.Target == "casse" {
			return false, "le service est arrete", nil
		}
		return true, "", nil
	})

	état := &ScopeState{
		Checks: map[string]SystemCheck{
			"essai|ok":    {Kind: "essai", Target: "ok", Expect: "active", StateKey: "m1"},
			"essai|casse": {Kind: "essai", Target: "casse", Expect: "active", StateKey: "m2"},
		},
	}

	rapport := scanFromState(état, ScopeMachine, "")

	if rapport.Checked != 2 {
		t.Errorf("%d controle(s), attendu 2 — un module sans fichier doit quand "+
			"meme compter dans le rapport", rapport.Checked)
	}
	if len(rapport.Items) != 1 {
		t.Fatalf("%d ecart(s), attendu 1 : %+v", len(rapport.Items), rapport.Items)
	}
	item := rapport.Items[0]
	if item.Kind != DriftSystemState {
		t.Errorf("type %q, attendu %q", item.Kind, DriftSystemState)
	}
	if item.Path != "casse" {
		t.Errorf("cible %q, attendu %q — Path porte la cible pour un ecart d'etat", item.Path, "casse")
	}
	if item.StateKey != "m2" {
		t.Errorf("StateKey %q, attendu m2 : sans lui la correction reapplique le mauvais module", item.StateKey)
	}
}

// TestUneVerificationImpossibleNEstPasUnEcart.
//
// La distinction qui compte le plus après la détection elle-même. Une commande
// absente, un délai dépassé : on ne sait pas, on ne constate pas. Les confondre
// ferait réappliquer un module — donc potentiellement relancer un service — sur
// une simple incertitude.
func TestUneVerificationImpossibleNEstPasUnEcart(t *testing.T) {
	avecChecker(t, "essai", func(c SystemCheck) (bool, string, error) {
		return false, "", fmt.Errorf("systemctl absent de cette machine")
	})

	état := &ScopeState{
		Checks: map[string]SystemCheck{
			"essai|x": {Kind: "essai", Target: "x", Expect: "active", StateKey: "m"},
		},
	}
	rapport := scanFromState(état, ScopeMachine, "")

	if len(rapport.Items) != 1 {
		t.Fatalf("%d ecart(s), attendu 1", len(rapport.Items))
	}
	if rapport.Items[0].Kind != DriftUnverifiable {
		t.Errorf("type %q, attendu %q : une incertitude n'est pas un constat",
			rapport.Items[0].Kind, DriftUnverifiable)
	}
}

// TestUneAttenteInconnueEstIgnoree.
//
// Une attente écrite par une version PLUS RÉCENTE de l'agent, ou dont le
// vérificateur a été retiré. Silence plutôt qu'écart : on ne sait pas constater,
// donc on ne constate rien. Signaler ferait réappliquer un module sans motif, à
// chaque cycle, indéfiniment.
func TestUneAttenteInconnueEstIgnoree(t *testing.T) {
	état := &ScopeState{
		Checks: map[string]SystemCheck{
			"venu_du_futur|x": {Kind: "venu_du_futur", Target: "x", StateKey: "m"},
		},
	}
	rapport := scanFromState(état, ScopeMachine, "")
	if len(rapport.Items) != 0 {
		t.Errorf("une attente non reconnue a produit un ecart : %+v", rapport.Items)
	}
}

// TestLOrdreDesEcartsEstStable.
//
// Un rapport dont l'ordre change à chaque exécution est illisible en
// comparaison — et c'est justement en comparant deux rapports qu'on cherche ce
// qui a bougé.
func TestLOrdreDesEcartsEstStable(t *testing.T) {
	avecChecker(t, "essai", func(c SystemCheck) (bool, string, error) {
		return false, "casse", nil
	})

	checks := map[string]SystemCheck{}
	for _, cible := range []string{"delta", "alpha", "charlie", "bravo"} {
		checks["essai|"+cible] = SystemCheck{Kind: "essai", Target: cible, StateKey: "m"}
	}
	état := &ScopeState{Checks: checks}

	var premier []string
	for i := 0; i < 5; i++ {
		var ordre []string
		for _, item := range scanFromState(état, ScopeMachine, "").Items {
			ordre = append(ordre, item.Path)
		}
		if i == 0 {
			premier = ordre
			continue
		}
		for j := range ordre {
			if ordre[j] != premier[j] {
				t.Fatalf("passage %d : ordre %v, attendu %v", i, ordre, premier)
			}
		}
	}
	if len(premier) != 4 || premier[0] != "alpha" {
		t.Errorf("ordre = %v, attendu trie par cible", premier)
	}
}

// --- attribution et cycle de vie --------------------------------------------

// TestUneAttenteEstAttribueeAuModuleQuiLaDeclare.
func TestUneAttenteEstAttribueeAuModuleQuiLaDeclare(t *testing.T) {
	ResetManifest()

	avant := checkSnapshot()
	recordCheck("essai", "unite-a", "active=started")
	deA := checksSince(avant, "module-a")

	if len(deA) != 1 {
		t.Fatalf("%d attente(s) attribuee(s), attendu 1", len(deA))
	}
	if deA["essai|unite-a"].StateKey != "module-a" {
		t.Errorf("attribuee a %q, attendu module-a", deA["essai|unite-a"].StateKey)
	}
}

// TestUneAttenteModifieeChangeDeModule.
//
// Deux modules peuvent surveiller la même cible avec des attentes différentes.
// Comparer les seules clés attribuerait la seconde au premier module, et la
// correction réappliquerait le mauvais.
func TestUneAttenteModifieeChangeDeModule(t *testing.T) {
	ResetManifest()

	recordCheck("essai", "unite", "active=started")
	avant := checkSnapshot()
	recordCheck("essai", "unite", "active=stopped")
	deB := checksSince(avant, "module-b")

	c, ok := deB["essai|unite"]
	if !ok {
		t.Fatal("l'attente modifiee n'a pas ete attribuee au second module")
	}
	if c.Expect != "active=stopped" || c.StateKey != "module-b" {
		t.Errorf("attente = %+v, attendu stopped/module-b", c)
	}
}

// TestResetManifestVideAussiLesAttentes.
//
// Les deux inventaires ont le même cycle de vie. Les vider séparément
// laisserait l'un survivre à l'autre, et une attente serait attribuée au module
// d'un cycle antérieur.
func TestResetManifestVideAussiLesAttentes(t *testing.T) {
	recordCheck("essai", "reste", "x")
	ResetManifest()
	if len(checkSnapshot()) != 0 {
		t.Error("les attentes ont survecu a ResetManifest")
	}
}

// TestLesAttentesDUnModuleDisparuQuittentLEtat.
//
// Une vérification orpheline signalerait éternellement un écart que plus aucun
// module ne sait corriger : le scan verrait un écart, la correction chercherait
// un module qui n'existe plus, et le cycle recommencerait indéfiniment.
func TestLesAttentesDUnModuleDisparuQuittentLEtat(t *testing.T) {
	précédent := &ScopeState{
		Modules: map[string]string{"reste": "fp", "parti": "fp"},
		Checks: map[string]SystemCheck{
			"essai|garde": {Kind: "essai", Target: "garde", StateKey: "reste"},
			"essai|orph":  {Kind: "essai", Target: "orph", StateKey: "parti"},
		},
	}
	politique := &Policy{
		Scope:   ScopeMachine,
		Modules: []Module{{Type: "t", StateKey: "reste", Fingerprint: "fp"}},
	}
	rapport := Report{
		Status:  StatusApplied,
		Modules: []ModuleOutcome{{StateKey: "reste", Result: ResultUnchanged}},
	}

	état := BuildScopeState(politique, précédent, rapport)

	if _, reste := état.Checks["essai|orph"]; reste {
		t.Error("l'attente d'un module disparu est restee dans l'etat")
	}
	if _, gardée := état.Checks["essai|garde"]; !gardée {
		t.Error("l'attente d'un module encore voulu a ete perdue : le scan " +
			"cesserait de surveiller un etat que la politique demande")
	}
}

// TestUnEtatAncienNaPasDAttentes : le champ Checks est ajouté, avec omitempty.
func TestUnEtatAncienNaPasDAttentes(t *testing.T) {
	état := &ScopeState{Modules: map[string]string{"m": "fp"}}
	if rapport := scanFromState(état, ScopeMachine, ""); !rapport.Conforming() {
		t.Errorf("un etat sans attentes produit des ecarts : %+v", rapport.Items)
	}
}

// --- les deux moitiés ensemble ----------------------------------------------

// TestFichiersEtEtatsSontRapportesEnsemble.
//
// Un scan rend UN rapport. Les deux inventaires n'ont pas à être consultés
// séparément par l'appelant, sinon chaque façade — cycle, CLI, page web —
// risquerait d'en oublier un.
func TestFichiersEtEtatsSontRapportesEnsemble(t *testing.T) {
	avecChecker(t, "essai", func(c SystemCheck) (bool, string, error) {
		return false, "service arrete", nil
	})

	dir := t.TempDir()
	disparu := filepath.Join(dir, "disparu.conf")

	état := &ScopeState{
		Modules: map[string]string{"m": "fp"},
		Files: map[string]FileState{
			disparu: {SHA256: "peu importe", Mode: 0o644, StateKey: "m"},
		},
		Checks: map[string]SystemCheck{
			"essai|svc": {Kind: "essai", Target: "svc", StateKey: "m"},
		},
	}

	rapport := scanFromState(état, ScopeMachine, "")

	if rapport.Checked != 2 {
		t.Errorf("%d controle(s), attendu 2 (un fichier + une attente)", rapport.Checked)
	}
	if len(rapport.Items) != 2 {
		t.Fatalf("%d ecart(s), attendu 2 : %+v", len(rapport.Items), rapport.Items)
	}

	kinds := map[DriftKind]bool{}
	for _, item := range rapport.Items {
		kinds[item.Kind] = true
	}
	if !kinds[DriftMissing] || !kinds[DriftSystemState] {
		t.Errorf("types rapportes = %v, attendu missing ET system_state", kinds)
	}

	// Un seul module concerné : la correction ne doit pas le réappliquer deux fois.
	if mods := rapport.ModulesConcerned(); len(mods) != 1 || mods[0] != "m" {
		t.Errorf("modules a reappliquer = %v, attendu [m]", mods)
	}
	_ = os.Remove(disparu)
}
