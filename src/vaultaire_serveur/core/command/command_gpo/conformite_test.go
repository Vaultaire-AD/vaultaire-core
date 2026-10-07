package commandgpo

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"vaultaire/core/action"
	dbgpo "vaultaire/core/database/db_gpo"
)

// `vlt gpo status` : une ligne par machine, comme la page — TO-DO 143.
//
// Les deux façades empruntent dbgpo.RegrouperParMachine. Ce test tient la
// moitié « ligne de commande » de l'invariant : mêmes lignes, mêmes cellules.

func parcDEssai(maintenant time.Time) []dbgpo.ComplianceRow {
	verifiee := sql.NullTime{Time: maintenant, Valid: true}
	hier := maintenant.Add(-26 * time.Hour)
	compte := func(machine, nom string, vu time.Time, ecarts int) dbgpo.ComplianceRow {
		return dbgpo.ComplianceRow{ComputeurID: machine, Scope: "user", TargetUser: nom, Status: "applied",
			ModulesTotal: 4, ReportedAt: vu, DriftAt: sql.NullTime{Time: vu, Valid: true}, DriftChecked: 5, DriftCount: ecarts}
	}
	return []dbgpo.ComplianceRow{
		{ComputeurID: "PC-01", Scope: "machine", Status: "applied", ModulesTotal: 3,
			ReportedAt: maintenant, DriftAt: verifiee, DriftChecked: 7},
		compte("PC-01", "alice@acme.lan", hier, 0),
		compte("PC-01", "bob@acme.lan", hier, 0),
		{ComputeurID: "PC-02", Scope: "machine", Status: "applied", ModulesTotal: 3,
			ReportedAt: maintenant, DriftAt: verifiee, DriftChecked: 7},
		compte("PC-02", "dora@acme.lan", maintenant, 2),
		compte("PC-02", "elsa@acme.lan", maintenant, 0),
	}
}

func lignesDe(sortie, motif string) []string {
	var out []string
	for _, l := range strings.Split(sortie, "\n") {
		if strings.Contains(l, motif) {
			out = append(out, l)
		}
	}
	return out
}

func TestStatusAUneLigneParMachine(t *testing.T) {
	maintenant := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	sortie := rendreConformiteA(parcDEssai(maintenant), false, maintenant)

	for _, machine := range []string{"PC-01", "PC-02"} {
		if n := len(lignesDe(sortie, machine)); n != 1 {
			t.Errorf("%s occupe %d ligne(s), attendu 1 :\n%s", machine, n, sortie)
		}
	}
	for _, absent := range []string{"alice@acme.lan", "bob@acme.lan", "elsa@acme.lan"} {
		if strings.Contains(sortie, absent) {
			t.Errorf("%s figure dans la liste alors que sa portée est conforme", absent)
		}
	}
	dora := lignesDe(sortie, "dora@acme.lan")
	if len(dora) != 1 || !strings.Contains(dora[0], "↳") || !strings.Contains(dora[0], "2 écart(s)") {
		t.Fatalf("le compte en écart ne remonte pas sous sa machine :\n%s", sortie)
	}
	if pc1 := lignesDe(sortie, "PC-01")[0]; !strings.Contains(pc1, "à jour") || !strings.Contains(pc1, "2 ok") ||
		!strings.Contains(pc1, "ok (7)") {
		t.Errorf("ligne de PC-01 : %q — attendu « à jour », « ok (7) » et « 2 ok »", pc1)
	}
	if pc2 := lignesDe(sortie, "PC-02")[0]; !strings.Contains(pc2, "1 en écart sur 2") {
		t.Errorf("ligne de PC-02 : %q — attendu « 1 en écart sur 2 »", pc2)
	}
	if strings.Contains(sortie, "en retard") {
		t.Errorf("une machine est « en retard » parce que des personnes ne sont plus connectées :\n%s", sortie)
	}
	if !strings.Contains(sortie, "2 machine(s) sur 2 suivie(s).") || !strings.Contains(sortie, "2 machine(s) : 1 avec écarts.") {
		t.Errorf("pied ou résumé inattendu :\n%s", sortie)
	}
	// L'ordre : ce qui va mal d'abord.
	if strings.Index(sortie, "PC-02") > strings.Index(sortie, "PC-01") {
		t.Errorf("la machine en écart n'est pas en tête :\n%s", sortie)
	}
}

// `gpo drift` : la machine dont SEUL un compte a dérivé y figure.
func TestDriftRetientLaMachineDontUnCompteADerive(t *testing.T) {
	maintenant := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	sortie := rendreConformiteA(parcDEssai(maintenant), true, maintenant)
	if len(lignesDe(sortie, "PC-02")) != 1 || !strings.Contains(sortie, "dora@acme.lan") {
		t.Fatalf("PC-02 est absente de la vue des écarts alors qu'un dossier personnel y a dérivé :\n%s", sortie)
	}
	if strings.Contains(sortie, "PC-01") {
		t.Errorf("PC-01, conforme, figure dans la vue des écarts :\n%s", sortie)
	}
	if !strings.Contains(sortie, "1 machine(s) sur 2 suivie(s).") {
		t.Errorf("le total du parc n'est pas rappelé :\n%s", sortie)
	}
}

func TestDriftSansRienASignaler(t *testing.T) {
	maintenant := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	sain := parcDEssai(maintenant)[:3]
	sortie := rendreConformiteA(sain, true, maintenant)
	if !strings.Contains(sortie, "sur les 1 machine(s) suivie(s)") {
		t.Errorf("message inattendu : %q", sortie)
	}
}

// TO-DO 169 : la commande sait demander un cycle aux machines d'une GPO, et le
// dit dans son usage et dans son aide.
func TestRefreshConnaitLesMachinesDUneGPO(t *testing.T) {
	usage := rafraichir(action.Appelant{Username: "admin"}, nil)
	for _, attendu := range []string{"<computeur_id>", "--gpo <nom>", "--all", "machines liées à une GPO"} {
		if !strings.Contains(usage, attendu) {
			t.Errorf("l'usage de « gpo refresh » ne dit pas %q :\n%s", attendu, usage)
		}
	}
	for _, args := range [][]string{{"--gpo"}, {"--gpo", "  "}} {
		if got := rafraichir(action.Appelant{Username: "admin"}, args); !strings.Contains(got, "Nom de GPO manquant") {
			t.Errorf("gpo refresh %v : %q", args, got)
		}
	}
}
