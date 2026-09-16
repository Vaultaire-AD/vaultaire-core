package gpo

import "testing"

// Le mode de dérive : d'où il vient, jusqu'où il va, et ce qu'il ne doit PAS
// faire bouger.
//
// Trois garanties sont vérifiées ici, et chacune ferme un défaut différent :
//
//  1. le mode descend de la GPO vers chacun de ses modules — sans quoi une
//     machine recevant une GPO en audit et une autre en enforce ne pourrait
//     appliquer la règle d'aucune des deux ;
//  2. il entre dans l'empreinte de POLITIQUE — sans quoi un passage en audit
//     n'atteindrait jamais le parc, le serveur répondant « rien à faire » ;
//  3. il n'entre PAS dans l'empreinte de MODULE — sans quoi un simple
//     changement de mode ferait réinstaller des paquets et relancer des
//     services sur tout le parc visé.

// politiqueDEssai rend une GPO machine d'un module, dans le mode demandé.
func politiqueDEssai(mode DriftMode) Policy {
	return Policy{
		ID:        1,
		Name:      "essai",
		Scope:     ScopeMachine,
		Version:   1,
		Enabled:   true,
		DriftMode: mode,
		Modules: []Module{{
			Type:       ModuleSysctl,
			Scope:      ScopeMachine,
			ApplyOrder: 11,
			Params:     map[string]string{"key": "net.ipv4.ip_forward", "value": "0"},
		}},
	}
}

// TestLeModeDescendVersLesModules.
func TestLeModeDescendVersLesModules(t *testing.T) {
	res := Resolve([]Policy{politiqueDEssai(DriftAudit)})

	if len(res.Machine) != 1 {
		t.Fatalf("modules effectifs = %d, attendu 1", len(res.Machine))
	}
	if mode := res.Machine[0].Module.EffectiveDriftMode(); mode != DriftAudit {
		t.Errorf("mode du module = %q, attendu %q", mode, DriftAudit)
	}
}

// TestEnforceResteImplicite.
//
// Le défaut n'est pas écrit, et ce n'est pas de l'économie de place : le champ
// entre dans l'empreinte de politique. L'écrire systématiquement changerait
// l'empreinte de TOUTES les GPO existantes au premier démarrage après mise à
// jour, et le parc entier retéléchargerait sa politique pour n'y trouver aucun
// module modifié.
func TestEnforceResteImplicite(t *testing.T) {
	res := Resolve([]Policy{politiqueDEssai(DriftEnforce)})

	if len(res.Machine) != 1 {
		t.Fatalf("modules effectifs = %d, attendu 1", len(res.Machine))
	}
	if brut := res.Machine[0].Module.DriftMode; brut != "" {
		t.Errorf("mode ecrit = %q, attendu vide — le defaut doit rester implicite", brut)
	}
	if mode := res.Machine[0].Module.EffectiveDriftMode(); mode != DriftEnforce {
		t.Errorf("mode effectif = %q, attendu %q", mode, DriftEnforce)
	}
}

// TestUneGPOSansModeGardeSonEmpreinte.
//
// C'est la garantie de migration : une base montée depuis une version
// antérieure a la colonne à vide, et son parc ne doit rien retélécharger.
func TestUneGPOSansModeGardeSonEmpreinte(t *testing.T) {
	sansMode := politiqueDEssai("")
	enforce := politiqueDEssai(DriftEnforce)

	avant, err := PolicyHash(fusionner(t, sansMode))
	if err != nil {
		t.Fatalf("empreinte sans mode : %v", err)
	}
	apres, err := PolicyHash(fusionner(t, enforce))
	if err != nil {
		t.Fatalf("empreinte enforce : %v", err)
	}

	if avant != apres {
		t.Errorf("l'empreinte a change entre une GPO sans mode et une GPO en enforce "+
			"(%s puis %s) : tout le parc retelechargerait sa politique a la migration",
			avant[:12], apres[:12])
	}
}

// TestLePassageEnAuditChangeLEmpreinteDePolitique.
//
// Sans cela le réglage serait lettre morte : le serveur compare l'empreinte
// annoncée par l'agent à celle qu'il calcule, et répond « rien à faire » quand
// elles coïncident. Le nouveau mode n'atteindrait le parc qu'à la prochaine
// modification de CONTENU — c'est-à-dire peut-être jamais.
func TestLePassageEnAuditChangeLEmpreinteDePolitique(t *testing.T) {
	enforce, err := PolicyHash(fusionner(t, politiqueDEssai(DriftEnforce)))
	if err != nil {
		t.Fatalf("empreinte enforce : %v", err)
	}
	audit, err := PolicyHash(fusionner(t, politiqueDEssai(DriftAudit)))
	if err != nil {
		t.Fatalf("empreinte audit : %v", err)
	}

	if enforce == audit {
		t.Error("l'empreinte de politique n'a pas bouge au passage en audit : " +
			"les agents recevraient « rien a faire » et garderaient l'ancien mode")
	}
}

// TestLeModeNeChangePasLEmpreinteDesModules.
//
// L'empreinte de module décide de ce qui est RÉAPPLIQUÉ. Le mode ne change pas
// ce qu'il faut poser sur la machine, seulement ce qu'on fait d'un écart : l'y
// inclure ferait réinstaller les paquets et relancer les services de tout un
// parc pour un réglage qui ne touche aucun fichier.
func TestLeModeNeChangePasLEmpreinteDesModules(t *testing.T) {
	moduleEnforce := fusionner(t, politiqueDEssai(DriftEnforce)).Modules[0]
	moduleAudit := fusionner(t, politiqueDEssai(DriftAudit)).Modules[0]

	empreinteEnforce, err := ModuleFingerprint(moduleEnforce)
	if err != nil {
		t.Fatalf("empreinte du module enforce : %v", err)
	}
	empreinteAudit, err := ModuleFingerprint(moduleAudit)
	if err != nil {
		t.Fatalf("empreinte du module audit : %v", err)
	}

	if empreinteEnforce != empreinteAudit {
		t.Error("l'empreinte du module a bouge avec le mode : un changement de " +
			"mode relancerait les services et reinstallerait les paquets du parc")
	}
}

// TestLeModeVoyageJusquAuDocumentLivre.
func TestLeModeVoyageJusquAuDocumentLivre(t *testing.T) {
	livree, err := BuildDeliveryPolicy(fusionner(t, politiqueDEssai(DriftAudit)), "")
	if err != nil {
		t.Fatalf("construction du document : %v", err)
	}
	if len(livree.Modules) != 1 {
		t.Fatalf("modules livres = %d, attendu 1", len(livree.Modules))
	}
	if livree.Modules[0].DriftMode != DriftAudit {
		t.Errorf("mode livre = %q, attendu %q", livree.Modules[0].DriftMode, DriftAudit)
	}
}

// TestDeuxGPODeModesDifferentsGardentChacuneLeSien.
//
// C'est la promesse qui a décidé de la granularité : un groupe « laboratoire »
// en audit ne doit pas désarmer le reste du parc, et le reste du parc ne doit
// pas ramener le laboratoire en enforce. Un mode unique par scope, quel que soit
// l'arbitrage retenu pour la fusion, trahirait forcément l'une des deux.
func TestDeuxGPODeModesDifferentsGardentChacuneLeSien(t *testing.T) {
	labo := politiqueDEssai(DriftAudit)
	labo.ID, labo.Name = 2, "laboratoire"
	labo.Modules[0].Params = map[string]string{"key": "kernel.dmesg_restrict", "value": "1"}

	res := Resolve([]Policy{politiqueDEssai(DriftEnforce), labo})

	if len(res.Conflicts) != 0 {
		t.Fatalf("conflits inattendus : %v", res.Conflicts)
	}
	if len(res.Machine) != 2 {
		t.Fatalf("modules effectifs = %d, attendu 2", len(res.Machine))
	}

	modes := map[string]DriftMode{}
	for _, eff := range res.Machine {
		modes[eff.PolicyName] = eff.Module.EffectiveDriftMode()
	}
	if modes["essai"] != DriftEnforce {
		t.Errorf("GPO essai en %q, attendu %q", modes["essai"], DriftEnforce)
	}
	if modes["laboratoire"] != DriftAudit {
		t.Errorf("GPO laboratoire en %q, attendu %q", modes["laboratoire"], DriftAudit)
	}
}

// TestNormalizeDriftMode.
func TestNormalizeDriftMode(t *testing.T) {
	valides := map[string]DriftMode{
		"":        DefaultDriftMode,
		"  ":      DefaultDriftMode,
		"enforce": DriftEnforce,
		"ENFORCE": DriftEnforce,
		" audit ": DriftAudit,
		"Audit":   DriftAudit,
	}
	for brut, attendu := range valides {
		mode, err := NormalizeDriftMode(brut)
		if err != nil {
			t.Errorf("NormalizeDriftMode(%q) a refuse : %v", brut, err)
			continue
		}
		if mode != attendu {
			t.Errorf("NormalizeDriftMode(%q) = %q, attendu %q", brut, mode, attendu)
		}
	}

	// Une faute de frappe est refusée et non ramenée au défaut : « enfrce »
	// deviendrait sinon silencieusement enforce aujourd'hui, et personne ne
	// verrait la faute le jour où le même geste voudra dire audit.
	for _, brut := range []string{"enfrce", "observe", "off", "true"} {
		if _, err := NormalizeDriftMode(brut); err == nil {
			t.Errorf("NormalizeDriftMode(%q) a ete accepte, attendu un refus", brut)
		}
	}
}

// fusionner rend la politique effective d'une GPO, comme le fait le serveur
// avant de la livrer. C'est ce passage qui pose le mode sur les modules.
func fusionner(t *testing.T, p Policy) Policy {
	t.Helper()
	merged, err := BuildPolicyForDelivery(p.Scope, []Policy{p})
	if err != nil {
		t.Fatalf("fusion de la GPO %s : %v", p.Name, err)
	}
	return merged
}
