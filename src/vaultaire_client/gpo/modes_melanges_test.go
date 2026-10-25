package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TO-DO 183 — deux GPO de modes différents sur la même machine (A_TESTER § 7e).
//
// La politique ci-dessous est celle que le core LIVRE pour deux GPO, l'une en
// audit et l'autre en enforce (sortie de BuildDeliveryPolicy, réduite aux
// champs utiles) : le mode voyage par module, absent quand il vaut enforce.
// Le test suit le chemin de l'agent jusqu'à la décision : état après
// application, fichiers cassés, scan, partage entre corrigés et signalés.

func politiqueDeuxModes(t *testing.T, fa, fb string) Policy {
	t.Helper()
	js := `{"name":"effective_machine","scope":"machine","version":2,"fingerprint":"fp","modules":[
{"type":"file_deploy","scope":"machine","params":{"path":"` + fa + `"},"state_key":"file_deploy:` + fa + `","fingerprint":"f1","drift_mode":"audit"},
{"type":"file_deploy","scope":"machine","params":{"path":"` + fb + `"},"state_key":"file_deploy:` + fb + `","fingerprint":"f2"}]}`
	var p Policy
	if err := json.Unmarshal([]byte(js), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func sha(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }

func TestDeuxGPODeModesDifferents(t *testing.T) {
	dir := t.TempDir()
	fa, fb := filepath.Join(dir, "audit.conf"), filepath.Join(dir, "enforce.conf")
	_ = os.WriteFile(fa, []byte("a"), 0o644)
	_ = os.WriteFile(fb, []byte("b"), 0o644)
	pol := politiqueDeuxModes(t, fa, fb)
	ka, kb := "file_deploy:"+fa, "file_deploy:"+fb

	état := BuildScopeState(&pol, nil, Report{Scope: ScopeMachine, Status: StatusApplied, Modules: []ModuleOutcome{
		{StateKey: ka, Result: ResultApplied, Files: map[string]FileState{fa: {SHA256: sha("a"), Mode: 0o644, StateKey: ka}}},
		{StateKey: kb, Result: ResultApplied, Files: map[string]FileState{fb: {SHA256: sha("b"), Mode: 0o644, StateKey: kb}}},
	}})
	if état.ModuleMode(ka) != DriftAudit || état.ModuleMode(kb) != DriftEnforce {
		t.Fatalf("modes = %v : chaque module doit garder celui de sa GPO", état.Modes)
	}

	_ = os.WriteFile(fa, []byte("cassé"), 0o644)
	_ = os.WriteFile(fb, []byte("cassé"), 0o644)
	rapport := scanFromState(état, ScopeMachine, "")
	marquerLesNonCorriges(état, &rapport)

	corriges, audites := partitionByMode(état, rapport.ModulesConcerned())
	if len(corriges) != 1 || corriges[0] != kb {
		t.Errorf("corrigés = %v, attendu [%s] : l'écart de la GPO en enforce doit être corrigé", corriges, kb)
	}
	if len(audites) != 1 || audites[0] != ka {
		t.Errorf("signalés = %v, attendu [%s]", audites, ka)
	}
	for _, item := range rapport.Items {
		if (item.StateKey == kb) == item.NonCorrige {
			t.Errorf("%s : NonCorrige = %v", item.Path, item.NonCorrige)
		}
	}
}

// Une attente d'état déclarée par deux modules, l'un en audit et l'autre en
// enforce : la seconde déclaration écrasait la première, et l'écart n'était
// attribué qu'au dernier déclarant. Le cas qui faisait passer une GPO en
// enforce pour une GPO en audit.
func TestUneAttentePartageeEngageLesDeuxModules(t *testing.T) {
	pol := Policy{Scope: ScopeMachine, Fingerprint: "fp", Modules: []Module{
		{Type: "systemd_service", StateKey: "enforce", Fingerprint: "f1"},
		{Type: "systemd_service", StateKey: "zz-audit", Fingerprint: "f2", DriftMode: string(DriftAudit)},
	}}
	attente := SystemCheck{Kind: "inconnu-du-test", Target: "sshd", Expect: "active"}
	avec := func(cle string) map[string]SystemCheck {
		c := attente
		c.StateKey = cle
		return map[string]SystemCheck{c.CheckID(): c}
	}
	état := BuildScopeState(&pol, nil, Report{Scope: ScopeMachine, Status: StatusApplied, Modules: []ModuleOutcome{
		{StateKey: "enforce", Result: ResultApplied, Checks: avec("enforce")},
		{StateKey: "zz-audit", Result: ResultApplied, Checks: avec("zz-audit")},
	}})

	c := état.Checks[attente.CheckID()]
	proprietaires := append([]string(nil), c.proprietaires()...)
	sort.Strings(proprietaires)
	if len(proprietaires) != 2 || proprietaires[0] != "enforce" || proprietaires[1] != "zz-audit" {
		t.Fatalf("déclarants = %v, attendu les deux modules", proprietaires)
	}

	rapport := DriftReport{Items: []DriftItem{{Path: "sshd", StateKey: c.StateKey,
		Coproprietaires: c.Owners, Kind: DriftSystemState}}}
	marquerLesNonCorriges(état, &rapport)
	if rapport.Items[0].NonCorrige {
		t.Error("l'écart est marqué non corrigé alors qu'un des modules est en enforce")
	}
	corriges, _ := partitionByMode(état, rapport.ModulesConcerned())
	if len(corriges) != 1 || corriges[0] != "enforce" {
		t.Errorf("corrigés = %v, attendu [enforce]", corriges)
	}

	// Le module en enforce retiré de la politique : l'attente reste, au seul
	// module qui la déclare encore.
	pol.Modules = pol.Modules[1:]
	état = BuildScopeState(&pol, état, Report{Scope: ScopeMachine, Status: StatusApplied, Modules: []ModuleOutcome{
		{StateKey: "zz-audit", Result: ResultUnchanged},
	}})
	if c := état.Checks[attente.CheckID()]; c.StateKey != "zz-audit" || len(c.Owners) != 0 {
		t.Errorf("après retrait : %+v", c)
	}
}
