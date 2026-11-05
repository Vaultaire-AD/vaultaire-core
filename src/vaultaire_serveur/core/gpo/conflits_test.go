package gpo

import "testing"

func chronyd(state string) Module {
	return Module{Type: ModuleSystemdService, ApplyOrder: 60,
		Params: map[string]string{"service": "chronyd", "state": state, "enabled": "unchanged", "masked": "false"}}
}

func fichier(chemin string) Module {
	return Module{Type: ModuleFileDeploy, ApplyOrder: 11,
		Params: map[string]string{"path": chemin, "content": "x", "mode": "0644", "state": "present"}}
}

func gpoDe(id int, nom string, mode DriftMode, version int, mods ...Module) Policy {
	return Policy{ID: id, Name: nom, Scope: ScopeMachine, Enabled: true, Version: version, DriftMode: mode, Modules: mods}
}

// TO-DO 222 : le même réglage dans deux GPO n'est pas un conflit — livré une
// fois, en enforce si l'une l'est.
func TestLeMemeReglageNEstPasUnConflit(t *testing.T) {
	audit := gpoDe(1, "essai_audit", DriftAudit, 3, chronyd("started"), fichier("/etc/a"))
	enforce := gpoDe(2, "essai_enforce", DriftEnforce, 5, chronyd("started"), fichier("/etc/e"))
	p, conflits, err := BuildPolicyForDelivery(ScopeMachine, []Policy{audit, enforce})
	if err != nil || len(conflits) != 0 {
		t.Fatalf("%v %v", err, conflits)
	}
	if len(p.Modules) != 3 {
		t.Fatalf("%d modules, 3 attendus (chronyd une fois, deux fichiers)", len(p.Modules))
	}
	for _, m := range p.Modules {
		switch m.Params["path"] + m.Params["service"] {
		case "chronyd":
			if m.DriftMode != "" {
				t.Errorf("chronyd en %q : l'enforce de l'une doit l'emporter", m.DriftMode)
			}
		case "/etc/a":
			if m.DriftMode != DriftAudit {
				t.Errorf("le fichier de la GPO en audit a perdu son mode : %q", m.DriftMode)
			}
		}
	}
	if p.Version != 8 {
		t.Errorf("version %d, 8 attendue (les deux GPO contribuent)", p.Version)
	}

	// Deux audits : le réglage commun reste en audit.
	audit2 := gpoDe(3, "autre_audit", DriftAudit, 1, chronyd("started"))
	res := Resolve([]Policy{audit, audit2})
	for _, e := range res.Machine {
		if e.Module.Type == ModuleSystemdService && (e.Module.DriftMode != DriftAudit || len(e.AussiPar) != 1) {
			t.Errorf("%+v", e)
		}
	}
}

// TO-DO 222 : deux réglages différents de la même chose — les deux modules
// sont écartés, le reste de chaque GPO est livré, le conflit est rendu.
func TestUnConflitNEcarteQueSesModules(t *testing.T) {
	a := gpoDe(1, "a", DriftEnforce, 1, chronyd("started"), fichier("/etc/a"))
	b := gpoDe(2, "b", DriftEnforce, 1, chronyd("stopped"), fichier("/etc/b"))
	c := gpoDe(3, "c", DriftEnforce, 1, chronyd("started")) // identique à a : écarté avec lui
	p, conflits, err := BuildPolicyForDelivery(ScopeMachine, []Policy{c, b, a})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflits) != 1 || conflits[0].Identity != "le service chronyd" {
		t.Fatalf("conflits : %v", conflits)
	}
	if len(p.Modules) != 2 {
		t.Fatalf("modules livrés : %+v", p.Modules)
	}
	for _, m := range p.Modules {
		if m.Type == ModuleSystemdService {
			t.Error("un module en conflit est livré")
		}
	}
	if want := `le service chronyd est réglé à la fois par la GPO "a" et par la GPO "b"`; DecrireConflits(conflits) != want {
		t.Errorf("%q", DecrireConflits(conflits))
	}

	// Lever le conflit en modifiant b change l'empreinte : sa version compte.
	b.Version = 2
	p2, _, _ := BuildPolicyForDelivery(ScopeMachine, []Policy{c, b, a})
	if p2.Version == p.Version {
		t.Error("la version d'une GPO en conflit n'entre pas dans la politique")
	}
}

// Le même chemin par deux types de module différents reste un conflit.
func TestMemeIdentiteAutreTypeEstUnConflit(t *testing.T) {
	tpl := Module{Type: ModuleTemplatedFile, ApplyOrder: 12, Params: map[string]string{"path": "/etc/a"}}
	res := Resolve([]Policy{gpoDe(1, "a", "", 1, fichier("/etc/a")), gpoDe(2, "b", "", 1, tpl)})
	if len(res.Conflicts) != 1 || len(res.Machine) != 0 {
		t.Fatalf("%+v", res)
	}
}
