package dbgpo

import (
	"database/sql"
	"testing"
	"time"
)

// Le parc, une ligne par machine — TO-DO 143.

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func verifieA(quand time.Time) sql.NullTime { return sql.NullTime{Time: quand, Valid: true} }

// porteeMachine rend une portée machine saine, rapportée à `vu`.
func porteeMachine(id string, vu time.Time) ComplianceRow {
	return ComplianceRow{ComputeurID: id, Scope: "machine", Status: "applied", ModulesTotal: 3,
		ReportedAt: vu, DriftAt: verifieA(vu), DriftChecked: 7}
}

// porteeCompte rend la portée saine d'un compte, rapportée à `vu`.
func porteeCompte(id, compte string, vu time.Time) ComplianceRow {
	return ComplianceRow{ComputeurID: id, Scope: "user", TargetUser: compte, Status: "applied",
		ModulesTotal: 4, ReportedAt: vu, DriftAt: verifieA(vu), DriftChecked: 5}
}

func TestUneMachineUneLigne(t *testing.T) {
	rows := []ComplianceRow{
		porteeCompte("pc-01", "bob@acme.lan", t0),
		porteeMachine("pc-01", t0),
		porteeCompte("pc-01", "alice@acme.lan", t0),
		porteeMachine("pc-02", t0),
	}
	lignes := RegrouperParMachine(rows, t0)
	if len(lignes) != 2 {
		t.Fatalf("%d ligne(s) pour 2 machines : la liste compte encore des portées", len(lignes))
	}
	pc1 := lignes[0]
	if pc1.ComputeurID != "pc-01" || !pc1.AMachine || pc1.Machine.Scope != "machine" {
		t.Fatalf("ligne de pc-01 : %+v", pc1)
	}
	if len(pc1.Comptes) != 2 || pc1.Comptes[0].TargetUser != "alice@acme.lan" {
		t.Fatalf("comptes de pc-01 : %+v — attendu alice puis bob, dans un ordre stable", pc1.Comptes)
	}
	if got := pc1.EtatDesComptes(); got != "2 ok" {
		t.Errorf("état des comptes : %q, attendu « 2 ok »", got)
	}
	if got := lignes[1].EtatDesComptes(); got != "-" {
		t.Errorf("machine sans compte : %q — « 0 ok » se lirait comme une conformité", got)
	}
	if len(pc1.ARemonter()) != 0 {
		t.Errorf("des comptes conformes remontent dans la liste : %+v", pc1.ARemonter())
	}
}

// Le défaut que le regroupement ferme : une personne partie depuis hier ne met
// pas sa machine « en retard ».
func TestLeSilenceDUnCompteNEstPasCeluiDeLaMachine(t *testing.T) {
	hier := t0.Add(-26 * time.Hour)
	rows := []ComplianceRow{
		porteeMachine("pc-01", t0.Add(-10*time.Minute)),
		porteeCompte("pc-01", "alice@acme.lan", hier),
	}
	l := RegrouperParMachine(rows, t0)[0]
	if l.Fraicheur(t0) != RapportAJour {
		t.Fatalf("machine %s alors que sa portée machine a rapporté il y a dix minutes : "+
			"c'est l'absence d'alice qui est comptée comme un silence de l'agent", l.Fraicheur(t0))
	}
	if l.ARetenirDansLaVueDesEcarts(t0) {
		t.Error("la machine entre dans la vue des écarts parce qu'un compte n'est pas connecté")
	}
	if r := ResumerParc(rows, t0); r.EnRetard != 0 || r.Lisible() != "1 machine(s), toutes à jour." {
		t.Fatalf("résumé : %q (%d en retard) — un parc dont les bureaux sont vides s'annonce en retard",
			r.Lisible(), r.EnRetard)
	}
	if !l.VuLe().Equal(t0.Add(-10 * time.Minute)) {
		t.Errorf("« vu » daté du compte et non de la machine : %s", l.VuLe())
	}
}

// Et l'inverse : un compte qui vient de se connecter ne masque pas un agent
// dont la portée machine ne rapporte plus.
func TestUnCompteRecentNeCachePasUneMachineMuette(t *testing.T) {
	rows := []ComplianceRow{
		porteeMachine("pc-01", t0.Add(-26*time.Hour)),
		porteeCompte("pc-01", "alice@acme.lan", t0),
	}
	l := RegrouperParMachine(rows, t0)[0]
	if l.Fraicheur(t0) != RapportEnRetard {
		t.Fatalf("machine %s : sa portée machine se tait depuis hier", l.Fraicheur(t0))
	}
	if ResumerParc(rows, t0).EnRetard != 1 {
		t.Error("le résumé ne compte pas la machine en retard")
	}
}

func TestUneMachineJamaisRapporteeResteMuette(t *testing.T) {
	rows := []ComplianceRow{NormaliserLigne(ComplianceRow{ComputeurID: "pc-09"}, sql.NullTime{})}
	l := RegrouperParMachine(rows, t0)[0]
	if l.Fraicheur(t0) != RapportJamais || !l.AMachine || l.Machine.ModulesAppliques() != "-" {
		t.Fatalf("machine jamais rapportée : %s, %+v", l.Fraicheur(t0), l)
	}
	if !l.ARetenirDansLaVueDesEcarts(t0) {
		t.Error("une machine muette sort de la vue des écarts")
	}
}

// Une machine qui n'a encore rapporté que pour un compte : datée par lui, faute
// de mieux, et sans inventer d'état pour une portée machine absente.
func TestSansPorteeMachineLeDernierRapportDate(t *testing.T) {
	rows := []ComplianceRow{
		porteeCompte("pc-01", "alice@acme.lan", t0.Add(-30*time.Minute)),
		porteeCompte("pc-01", "bob@acme.lan", t0.Add(-5*time.Minute)),
	}
	l := RegrouperParMachine(rows, t0)[0]
	if l.AMachine {
		t.Fatal("une portée machine a été inventée")
	}
	if !l.VuLe().Equal(t0.Add(-5*time.Minute)) || l.Fraicheur(t0) != RapportAJour {
		t.Fatalf("vu %s, %s", l.VuLe(), l.Fraicheur(t0))
	}
}

// Ce qui remonte sous la machine, et ce qui reste dans la fiche.
func TestSeulsLesComptesAMontrerRemontent(t *testing.T) {
	derive := porteeCompte("pc-01", "alice@acme.lan", t0)
	derive.DriftCount = 2
	echec := porteeCompte("pc-01", "bob@acme.lan", t0)
	echec.ModulesFailed, echec.Status = 1, "partial"
	jamaisVerifie := porteeCompte("pc-01", "carl@acme.lan", t0)
	jamaisVerifie.DriftAt = sql.NullTime{}
	sain := porteeCompte("pc-01", "dora@acme.lan", t0)
	// Une portée sans aucun module n'a rien à vérifier : elle ne remonte pas.
	vide := porteeCompte("pc-01", "elsa@acme.lan", t0)
	vide.ModulesTotal, vide.DriftAt = 0, sql.NullTime{}

	l := RegrouperParMachine([]ComplianceRow{
		porteeMachine("pc-01", t0), sain, derive, echec, jamaisVerifie, vide}, t0)[0]

	var noms []string
	for _, c := range l.ARemonter() {
		noms = append(noms, c.TargetUser)
	}
	if len(noms) != 3 || noms[0] != "alice@acme.lan" || noms[1] != "bob@acme.lan" || noms[2] != "carl@acme.lan" {
		t.Fatalf("remontés : %v — attendu alice (écart), bob (échec), carl (jamais vérifié)", noms)
	}
	if got, veut := l.EtatDesComptes(), "1 en écart, 1 en échec, 1 non vérifié(s) sur 5"; got != veut {
		t.Errorf("état des comptes : %q, attendu %q", got, veut)
	}
}

// Le pire état l'emporte : une machine dont un dossier personnel a dérivé n'est
// pas conforme parce que sa portée machine l'est.
func TestLePireEtatLEmporte(t *testing.T) {
	derive := porteeCompte("pc-02", "alice@acme.lan", t0)
	derive.DriftCount = 3
	echec := porteeCompte("pc-03", "bob@acme.lan", t0)
	echec.ModulesFailed = 1
	rows := []ComplianceRow{
		porteeMachine("pc-01", t0),
		porteeMachine("pc-02", t0), derive,
		porteeMachine("pc-03", t0), echec,
		porteeMachine("pc-04", t0.Add(-26*time.Hour)),
	}
	lignes := RegrouperParMachine(rows, t0)
	var ordre []string
	for _, l := range lignes {
		ordre = append(ordre, l.ComputeurID)
	}
	// Silence, puis échec, puis écarts, puis le reste.
	veut := []string{"pc-04", "pc-03", "pc-02", "pc-01"}
	for i := range veut {
		if ordre[i] != veut[i] {
			t.Fatalf("ordre %v, attendu %v", ordre, veut)
		}
	}

	pc2 := lignes[2]
	if pc2.Machine.EtatConformite() != "ok (7)" || pc2.Ecarts() != 3 || !pc2.ARetenirDansLaVueDesEcarts(t0) {
		t.Fatalf("pc-02 : portée machine %q, %d écart(s), vue des écarts %v — l'écart d'un compte doit compter "+
			"pour la machine sans maquiller sa portée machine",
			pc2.Machine.EtatConformite(), pc2.Ecarts(), pc2.ARetenirDansLaVueDesEcarts(t0))
	}
	if lignes[3].ARetenirDansLaVueDesEcarts(t0) {
		t.Error("une machine saine figure dans la vue des écarts")
	}

	r := ResumerParc(rows, t0)
	if r.Machines != 4 || r.EnRetard != 1 || r.EnEchec != 1 || r.AvecEcarts != 1 {
		t.Fatalf("résumé : %+v", r)
	}
}

func TestLeRegroupementEstDeterministe(t *testing.T) {
	a := []ComplianceRow{
		porteeCompte("pc-02", "bob@acme.lan", t0), porteeMachine("pc-01", t0),
		porteeCompte("pc-02", "alice@acme.lan", t0), porteeMachine("pc-02", t0),
	}
	b := []ComplianceRow{a[3], a[2], a[1], a[0]}
	la, lb := RegrouperParMachine(a, t0), RegrouperParMachine(b, t0)
	if len(la) != len(lb) {
		t.Fatal("tailles différentes")
	}
	for i := range la {
		if la[i].ComputeurID != lb[i].ComputeurID || len(la[i].Comptes) != len(lb[i].Comptes) {
			t.Fatalf("rang %d : %s / %s", i, la[i].ComputeurID, lb[i].ComputeurID)
		}
		for j := range la[i].Comptes {
			if la[i].Comptes[j].TargetUser != lb[i].Comptes[j].TargetUser {
				t.Fatalf("comptes de %s dans un ordre qui dépend de l'entrée", la[i].ComputeurID)
			}
		}
	}
}
