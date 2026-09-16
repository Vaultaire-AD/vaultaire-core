package dbgpo

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// Les libellés de conformité, partagés par la ligne de commande et le portail.
//
// # Pourquoi ils sont ici et pas dans une façade
//
// Ils ont vécu en privé dans `commandgpo`. Tant qu'il n'y avait qu'une façade,
// cela n'avait aucune conséquence. Le jour où le portail a eu sa page, il n'avait
// que deux choix : les recopier, ou les remonter.
//
// Recopier aurait produit deux vues qui disent PRESQUE la même chose. Presque est
// le pire cas : personne ne remarque l'écart tant qu'il est petit, et quand il
// grandit, on ne sait plus laquelle des deux avait raison — alors que c'est
// justement la vue qu'on consulte quand quelque chose ne va pas.

func ligne(mod func(*ComplianceRow)) ComplianceRow {
	r := ComplianceRow{
		ComputeurID: "PC-01", Scope: "machine",
		ModulesTotal: 10, ModulesFailed: 0,
		ReportedAt: time.Now().UTC(),
	}
	if mod != nil {
		mod(&r)
	}
	return r
}

// TestJamaisVerifieNestPasConforme.
//
// LE test de ce fichier. Une machine que personne n'a scannée affiche zéro
// écart — non parce qu'elle est saine, mais parce que rien n'a été regardé.
// Afficher un zéro rassurant est la seule erreur d'affichage qui puisse faire
// conclure à tort qu'un parc va bien.
func TestJamaisVerifieNestPasConforme(t *testing.T) {
	jamais := ligne(func(r *ComplianceRow) { r.DriftAt = sql.NullTime{} })
	conforme := ligne(func(r *ComplianceRow) {
		r.DriftAt = sql.NullTime{Time: time.Now(), Valid: true}
		r.DriftChecked = 12
	})

	if got := jamais.EtatConformite(); got != "non vérifié" {
		t.Errorf("machine jamais scannée = %q, attendu « non vérifié »", got)
	}
	if got := conforme.EtatConformite(); got == jamais.EtatConformite() {
		t.Errorf("une machine scannée et une machine jamais scannée rendent le "+
			"même libellé %q : on ne peut plus les distinguer", got)
	}
	if strings.Contains(jamais.EtatConformite(), "0") {
		t.Errorf("libellé %q : un zéro se lit comme une réussite", jamais.EtatConformite())
	}
}

func TestEtatConformiteCompteLesEcarts(t *testing.T) {
	avec := ligne(func(r *ComplianceRow) {
		r.DriftAt = sql.NullTime{Time: time.Now(), Valid: true}
		r.DriftCount = 3
	})
	if got := avec.EtatConformite(); !strings.Contains(got, "3") {
		t.Errorf("libellé %q : ne dit pas combien d'écarts", got)
	}
}

// TestModulesJamaisRapportesNeDisentPasZeroSurZero.
//
// « 0/0 » se lit comme « aucun module à appliquer », c'est-à-dire comme une
// réussite. Une machine qui n'a jamais rapporté n'a rien appliqué du tout.
func TestModulesJamaisRapportesNeDisentPasZeroSurZero(t *testing.T) {
	muette := ligne(func(r *ComplianceRow) {
		r.JamaisRapporte = true
		r.ModulesTotal, r.ModulesFailed = 0, 0
	})
	if got := muette.ModulesAppliques(); got == "0/0" {
		t.Error("« 0/0 » pour une machine muette : se lit comme une réussite")
	}
	if got := muette.ModulesAppliques(); got != "-" {
		t.Errorf("libellé = %q, attendu « - »", got)
	}

	normale := ligne(func(r *ComplianceRow) { r.ModulesTotal, r.ModulesFailed = 10, 2 })
	if got := normale.ModulesAppliques(); got != "8/10" {
		t.Errorf("libellé = %q, attendu « 8/10 »", got)
	}
}

// TestLaVueDesEcartsGardeLesMachinesMuettes.
//
// Une machine qui ne rapporte plus a zéro écart constaté parce que plus personne
// ne regarde. La retirer d'une vue qui cherche les problèmes reviendrait à
// cacher le seul cas où l'on ne sait rien.
func TestLaVueDesEcartsGardeLesMachinesMuettes(t *testing.T) {
	maintenant := time.Now().UTC()

	muette := ligne(func(r *ComplianceRow) { r.JamaisRapporte = true; r.DriftCount = 0 })
	enRetard := ligne(func(r *ComplianceRow) {
		r.ReportedAt = maintenant.Add(-ToleranceRapport - time.Hour)
		r.DriftCount = 0
	})
	saine := ligne(func(r *ComplianceRow) { r.DriftCount = 0 })
	enEcart := ligne(func(r *ComplianceRow) { r.DriftCount = 2 })

	cas := []struct {
		nom     string
		r       ComplianceRow
		attendu bool
	}{
		{"jamais rapporté", muette, true},
		{"en retard", enRetard, true},
		{"saine et à jour", saine, false},
		{"en écart", enEcart, true},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if got := c.r.ARetenirDansLaVueDesEcarts(maintenant); got != c.attendu {
				t.Errorf("retenue = %v, attendu %v", got, c.attendu)
			}
		})
	}
}

func TestAgeRelatif(t *testing.T) {
	maintenant := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

	cas := []struct {
		nom      string
		t        time.Time
		attendue string
	}{
		{"jamais", time.Time{}, "jamais"},
		{"à l'instant", maintenant.Add(-30 * time.Second), "à l'instant"},
		{"minutes", maintenant.Add(-20 * time.Minute), "il y a 20min"},
		{"heures", maintenant.Add(-5 * time.Hour), "il y a 5h"},
		{"jours", maintenant.Add(-72 * time.Hour), "il y a 3j"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if got := AgeRelatif(c.t, maintenant); got != c.attendue {
				t.Errorf("AgeRelatif = %q, attendu %q", got, c.attendue)
			}
		})
	}
}

// TestResumeCompteLesMachinesPasLesLignes.
//
// Une machine dont deux portées sont en échec est UN problème, pas deux. Compter
// les lignes gonflerait les chiffres à proportion du nombre d'utilisateurs
// connectés, et « 47 échecs » sur douze machines ne veut rien dire.
func TestResumeCompteLesMachinesPasLesLignes(t *testing.T) {
	maintenant := time.Now().UTC()
	rows := []ComplianceRow{
		{ComputeurID: "PC-01", Scope: "machine", ReportedAt: maintenant, ModulesFailed: 1},
		{ComputeurID: "PC-01", Scope: "user", TargetUser: "alice", ReportedAt: maintenant, ModulesFailed: 2},
		{ComputeurID: "PC-01", Scope: "user", TargetUser: "bob", ReportedAt: maintenant, ModulesFailed: 1},
	}

	r := ResumerParc(rows, maintenant)
	if r.Machines != 1 {
		t.Errorf("Machines = %d, attendu 1", r.Machines)
	}
	if r.EnEchec != 1 {
		t.Errorf("EnEchec = %d, attendu 1 — trois lignes d'une même machine "+
			"font un problème, pas trois", r.EnEchec)
	}

	lisible := r.Lisible()
	if !strings.Contains(lisible, "1 machine") || !strings.Contains(lisible, "1 en échec") {
		t.Errorf("résumé = %q", lisible)
	}
}

func TestResumeToutesAJour(t *testing.T) {
	maintenant := time.Now().UTC()
	rows := []ComplianceRow{
		{ComputeurID: "PC-01", ReportedAt: maintenant},
		{ComputeurID: "PC-02", ReportedAt: maintenant},
	}
	if got := ResumerParc(rows, maintenant).Lisible(); !strings.Contains(got, "toutes à jour") {
		t.Errorf("résumé = %q, attendu « toutes à jour »", got)
	}
}
