package dbgpo

import (
	"database/sql"
	"testing"
	"time"
)

// maintenant est l'instant de référence de tous les tests de ce fichier.
//
// Fixe, et non time.Now() : un test dont le résultat dépend de l'heure à
// laquelle il est lancé finit par échouer un jour de changement d'heure, et on
// le désactive au lieu de le comprendre.
var maintenant = time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)

func ligne(id string, ageDuRapport time.Duration, echecs, ecarts int) ComplianceRow {
	return ComplianceRow{
		ComputeurID:   id,
		Scope:         "machine",
		ReportedAt:    maintenant.Add(-ageDuRapport),
		ModulesFailed: echecs,
		DriftCount:    ecarts,
	}
}

// ligneMuette passe par NormaliserLigne plutôt que de recopier son résultat.
//
// Fabriquer la ligne à la main reviendrait à vérifier la constante contre
// elle-même : c'est ce que faisait la première version, et une mutation
// remplaçant ScopeInconnu par une chaîne vide passait inaperçue.
func ligneMuette(id string) ComplianceRow {
	return NormaliserLigne(ComplianceRow{ComputeurID: id}, sql.NullTime{})
}

// TestUneLigneSansRapportEstMarqueeMuette : la conclusion de la LEFT JOIN.
//
// Une machine de l'inventaire sans ligne de conformité arrive ici avec un
// reported_at NULL. C'est le seul indice, et tout en découle : le drapeau, la
// portée affichée, la place en tête de tableau.
func TestUneLigneSansRapportEstMarqueeMuette(t *testing.T) {
	r := NormaliserLigne(ComplianceRow{ComputeurID: "poste-neuf"}, sql.NullTime{})

	if !r.JamaisRapporte {
		t.Error("une ligne sans date de rapport n'est pas marquée muette : " +
			"la machine se confondrait avec une machine à jour")
	}
	if r.Scope == "" {
		t.Error("la portée est laissée vide : une case vide se lit comme une " +
			"donnée manquante, pas comme « on ne sait pas »")
	}
	if r.Scope != ScopeInconnu {
		t.Errorf("portée %q, attendu %q", r.Scope, ScopeInconnu)
	}
	if !r.ReportedAt.IsZero() {
		t.Error("une date a été inventée pour une machine qui n'a rien dit")
	}
}

// TestUneLigneAvecRapportGardeSaDate : le cas nominal ne doit pas être abîmé.
func TestUneLigneAvecRapportGardeSaDate(t *testing.T) {
	quand := maintenant.Add(-90 * time.Minute)
	r := NormaliserLigne(
		ComplianceRow{ComputeurID: "poste-1", Scope: "machine"},
		sql.NullTime{Time: quand, Valid: true})

	if r.JamaisRapporte {
		t.Error("une ligne AVEC rapport est marquée muette")
	}
	if !r.ReportedAt.Equal(quand) {
		t.Errorf("date %s, attendu %s", r.ReportedAt, quand)
	}
	if r.Scope != "machine" {
		t.Errorf("la portée réelle a été écrasée : %q", r.Scope)
	}
}

// TestFraicheurQualifieLesTroisEtats.
//
// La tolérance vaut TROIS cycles. Les bornes comptent : à exactement trois
// heures la machine est encore à jour, une seconde plus tard elle ne l'est
// plus. Tester au milieu de chaque intervalle laisserait passer une comparaison
// écrite avec le mauvais sens.
func TestFraicheurQualifieLesTroisEtats(t *testing.T) {
	cas := []struct {
		nom     string
		ligne   ComplianceRow
		attendu EtatRapport
	}{
		{"jamais rapporté", ligneMuette("m1"), RapportJamais},
		{"date nulle sans le drapeau", ComplianceRow{ComputeurID: "m2"}, RapportJamais},
		{"rapport à l'instant", ligne("m3", 0, 0, 0), RapportAJour},
		{"un cycle manqué", ligne("m4", IntervalleRapportAgent, 0, 0), RapportAJour},
		{"deux cycles manqués", ligne("m5", 2*IntervalleRapportAgent, 0, 0), RapportAJour},
		{"pile la tolérance", ligne("m6", ToleranceRapport, 0, 0), RapportAJour},
		{"une seconde après", ligne("m7", ToleranceRapport+time.Second, 0, 0), RapportEnRetard},
		{"trois semaines", ligne("m8", 21*24*time.Hour, 0, 0), RapportEnRetard},
	}
	for _, c := range cas {
		if got := c.ligne.Fraicheur(maintenant); got != c.attendu {
			t.Errorf("%s : %q, attendu %q", c.nom, got, c.attendu)
		}
	}
}

// TestUnCycleManqueNeDeclencheRien : le point de réglage.
//
// Signaler au premier cycle manqué remplirait la vue de retards qui se
// résolvent seuls — un redémarrage, une coupure brève — et l'administrateur
// cesserait de la lire. Une vue qu'on ne lit plus ne signale rien du tout.
func TestUnCycleManqueNeDeclencheRien(t *testing.T) {
	r := ligne("poste-12", IntervalleRapportAgent+time.Minute, 0, 0)
	if r.Silencieuse(maintenant) {
		t.Error("un seul cycle manqué est signalé comme un retard : " +
			"un simple redémarrage ferait du bruit")
	}
}

// TestSilencieusePasseAvantEchec — LE test de l'ordre.
//
// Un échec est un problème avéré, un silence n'est peut-être rien. C'est
// justement pourquoi le silence passe devant : un échec est chiffré et
// actionnable, un silence ne dit rien — la machine peut être éteinte, ou avoir
// dérivé depuis trois semaines sans que personne ne l'apprenne.
func TestSilencieusePasseAvantEchec(t *testing.T) {
	rows := []ComplianceRow{
		ligne("b-en-echec", 0, 3, 0),
		ligneMuette("a-muette"),
	}
	TrierConformite(rows, maintenant)

	if rows[0].ComputeurID != "a-muette" {
		t.Errorf("premier = %q, attendu a-muette : "+
			"une machine dont on ne sait RIEN doit passer avant une machine "+
			"dont on connaît le problème", rows[0].ComputeurID)
	}
}

func TestOrdreCompletDuTri(t *testing.T) {
	rows := []ComplianceRow{
		ligne("e-saine", 0, 0, 0),
		ligne("d-un-ecart", 0, 0, 1),
		ligne("c-trois-ecarts", 0, 0, 3),
		ligne("b-en-echec", 0, 2, 0),
		ligne("a-en-retard", ToleranceRapport+time.Hour, 0, 0),
	}
	TrierConformite(rows, maintenant)

	attendu := []string{"a-en-retard", "b-en-echec", "c-trois-ecarts", "d-un-ecart", "e-saine"}
	for i, veut := range attendu {
		if rows[i].ComputeurID != veut {
			t.Fatalf("position %d : %q, attendu %q — ordre obtenu : %v",
				i, rows[i].ComputeurID, veut, identifiants(rows))
		}
	}
}

// TestLeTriEstDeterministe : deux exécutions rendent le même tableau.
//
// Un ordre qui change d'une commande à l'autre sur des données identiques rend
// toute comparaison impossible — « ça a bougé depuis hier ? » n'a plus de
// réponse.
func TestLeTriEstDeterministe(t *testing.T) {
	construire := func() []ComplianceRow {
		return []ComplianceRow{
			{ComputeurID: "poste-2", Scope: "user", TargetUser: "bob"},
			{ComputeurID: "poste-1", Scope: "machine"},
			{ComputeurID: "poste-2", Scope: "user", TargetUser: "alice"},
			{ComputeurID: "poste-2", Scope: "machine"},
		}
	}
	a, b := construire(), construire()
	// Toutes ces lignes ont ReportedAt nul, donc « jamais » : le départage se
	// fait sur l'identifiant, la portée puis l'utilisateur.
	TrierConformite(a, maintenant)
	TrierConformite(b, maintenant)

	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("position %d diffère entre deux tris identiques", i)
		}
	}
	attendu := []string{"poste-1", "poste-2", "poste-2", "poste-2"}
	for i, veut := range attendu {
		if a[i].ComputeurID != veut {
			t.Errorf("position %d : %q, attendu %q", i, a[i].ComputeurID, veut)
		}
	}
	if a[1].Scope != "machine" {
		t.Errorf("à identifiant égal, la portée départage : %q avant %q", a[1].Scope, a[2].Scope)
	}
	if a[2].TargetUser != "alice" {
		t.Errorf("à portée égale, l'utilisateur départage : %q", a[2].TargetUser)
	}
}

// TestResumeCompteDesMachinesPasDesLignes.
//
// Une machine dont trois portées sont en échec est UN problème. Compter les
// lignes gonflerait le chiffre à proportion du nombre d'utilisateurs connectés,
// et « 47 échecs » sur douze machines ne veut rien dire.
func TestResumeCompteDesMachinesPasDesLignes(t *testing.T) {
	rows := []ComplianceRow{
		{ComputeurID: "poste-1", Scope: "machine", ReportedAt: maintenant, ModulesFailed: 1},
		{ComputeurID: "poste-1", Scope: "user", TargetUser: "alice", ReportedAt: maintenant, ModulesFailed: 2},
		{ComputeurID: "poste-1", Scope: "user", TargetUser: "bob", ReportedAt: maintenant, ModulesFailed: 1},
		{ComputeurID: "poste-2", Scope: "machine", ReportedAt: maintenant},
	}
	r := ResumerParc(rows, maintenant)

	if r.Machines != 2 {
		t.Errorf("machines = %d, attendu 2", r.Machines)
	}
	if r.EnEchec != 1 {
		t.Errorf("en échec = %d, attendu 1 : trois portées d'une même machine "+
			"comptent pour une machine", r.EnEchec)
	}
}

func TestResumeDistingueJamaisEtEnRetard(t *testing.T) {
	rows := []ComplianceRow{
		ligneMuette("jamais-vue"),
		ligne("partie-depuis", ToleranceRapport+time.Hour, 0, 0),
		ligne("a-jour", time.Minute, 0, 2),
	}
	r := ResumerParc(rows, maintenant)

	if r.Jamais != 1 {
		t.Errorf("jamais = %d, attendu 1", r.Jamais)
	}
	if r.EnRetard != 1 {
		t.Errorf("en retard = %d, attendu 1 — confondre les deux effacerait "+
			"la différence entre une machine jamais installée et un agent mort", r.EnRetard)
	}
	if r.AvecEcarts != 1 {
		t.Errorf("avec écarts = %d, attendu 1", r.AvecEcarts)
	}
	if r.Machines != 3 {
		t.Errorf("machines = %d, attendu 3", r.Machines)
	}
}

func TestParcEntierementAJour(t *testing.T) {
	rows := []ComplianceRow{ligne("a", time.Minute, 0, 0), ligne("b", time.Hour, 0, 0)}
	r := ResumerParc(rows, maintenant)
	if r.Jamais+r.EnRetard+r.EnEchec+r.AvecEcarts != 0 {
		t.Errorf("un parc sain remonte des anomalies : %+v", r)
	}
	if r.Machines != 2 {
		t.Errorf("machines = %d, attendu 2", r.Machines)
	}
}

func identifiants(rows []ComplianceRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ComputeurID)
	}
	return out
}
