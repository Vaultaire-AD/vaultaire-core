package webserveur

import (
	"bytes"
	"database/sql"
	"html/template"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dbgpo "vaultaire/core/database/db_gpo"
)

// La page Conformité, EXÉCUTÉE : un champ mal nommé passe la compilation et ne
// casse qu'à la première visite.

// rendreLaPage joue le gabarit sur des lignes, comme le fait le gestionnaire.
func rendreLaPage(t *testing.T, rows []dbgpo.ComplianceRow, maintenant time.Time) string {
	t.Helper()
	machines := dbgpo.RegrouperParMachine(rows, maintenant)
	data := struct {
		Username    string
		DnsEnable   bool
		Section     string
		Message     string
		Resume      string
		Lignes      []conformiteVue
		Total       int
		EcartsSeuls bool
		Vide        bool
	}{Username: "root", Section: "conformite", Total: len(machines),
		Resume: dbgpo.ResumerParc(rows, maintenant).Lisible()}
	for _, m := range machines {
		data.Lignes = append(data.Lignes, vueDeMachine(m, maintenant))
	}

	tmpl, err := template.ParseFiles(
		filepath.Join(cheminGabarits, "admin_sidebar.html"),
		filepath.Join(cheminGabarits, "admin_gpo_compliance.html"))
	if err != nil {
		t.Fatalf("analyse du gabarit : %v", err)
	}
	var page bytes.Buffer
	if err := tmpl.ExecuteTemplate(&page, "admin_gpo_compliance.html", data); err != nil {
		t.Fatalf("exécution du gabarit : %v", err)
	}
	return page.String()
}

// La page fait ressortir une portée jamais vérifiée (TO-DO 135).
//
// « non vérifié » s'affichait en texte nu, entre deux « ok » : la cellule se
// lisait comme une valeur parmi d'autres, et le résumé concluait « toutes à
// jour ». C'est ce qui a laissé le scope utilisateur sans aucune vérification
// pendant des semaines sans que personne ne s'en étonne.
func TestLaPageConformiteFaitRessortirLeNonVerifie(t *testing.T) {
	maintenant := time.Now()
	verifiee := sql.NullTime{Time: maintenant, Valid: true}
	html := rendreLaPage(t, []dbgpo.ComplianceRow{
		{ComputeurID: "PC-01", Scope: "machine", Status: "applied", ModulesTotal: 3,
			ReportedAt: maintenant, DriftAt: verifiee, DriftChecked: 7},
		{ComputeurID: "PC-01", Scope: "user", TargetUser: "alice@acme.lan", Status: "applied",
			ModulesTotal: 4, ReportedAt: maintenant},
	}, maintenant)

	if !strings.Contains(html, `<span class="badge badge-danger">non vérifié</span>`) {
		t.Error("la portée jamais vérifiée n'est pas mise en avant")
	}
	if strings.Contains(html, `<span class="badge badge-danger">ok (7)</span>`) {
		t.Error("une portée vérifiée et conforme est affichée comme un problème")
	}
	if !strings.Contains(html, "ok (7)") {
		t.Error("l'état de la portée vérifiée a disparu")
	}
	if strings.Contains(html, "toutes à jour") || !strings.Contains(html, "jamais vérifiée") {
		t.Errorf("le résumé ne dit pas qu'une portée n'a jamais été vérifiée")
	}
	// Elle remonte sous sa machine, nommée — sinon le chiffre du résumé ne se
	// retrouve sur aucune ligne.
	if !strings.Contains(html, "alice@acme.lan") {
		t.Error("le compte jamais vérifié ne remonte pas sous sa machine")
	}
}

// Une ligne par machine (TO-DO 143).
func TestLaPageConformiteAUneLigneParMachine(t *testing.T) {
	maintenant := time.Now()
	verifiee := sql.NullTime{Time: maintenant, Valid: true}
	hier := maintenant.Add(-26 * time.Hour)
	compte := func(machine, nom string, vu time.Time, ecarts int) dbgpo.ComplianceRow {
		return dbgpo.ComplianceRow{ComputeurID: machine, Scope: "user", TargetUser: nom, Status: "applied",
			ModulesTotal: 4, ReportedAt: vu, DriftAt: sql.NullTime{Time: vu, Valid: true}, DriftChecked: 5, DriftCount: ecarts}
	}
	html := rendreLaPage(t, []dbgpo.ComplianceRow{
		{ComputeurID: "PC-01", Scope: "machine", Status: "applied", ModulesTotal: 3,
			ReportedAt: maintenant, DriftAt: verifiee, DriftChecked: 7},
		// Trois personnes passées sur le poste, parties depuis hier, conformes.
		compte("PC-01", "alice@acme.lan", hier, 0),
		compte("PC-01", "bob@acme.lan", hier, 0),
		compte("PC-01", "carl@acme.lan", hier, 0),
		{ComputeurID: "PC-02", Scope: "machine", Status: "applied", ModulesTotal: 3,
			ReportedAt: maintenant, DriftAt: verifiee, DriftChecked: 7},
		compte("PC-02", "dora@acme.lan", maintenant, 2),
		compte("PC-02", "elsa@acme.lan", maintenant, 0),
	}, maintenant)

	// Deux machines : deux liens vers une fiche, pas sept.
	if n := strings.Count(html, `<a href="/admin/gpo/compliance?machine=`); n != 2 {
		t.Errorf("%d lien(s) de machine dans la liste, attendu 2 : une ligne par portée est revenue", n)
	}
	for _, absent := range []string{"alice@acme.lan", "bob@acme.lan", "carl@acme.lan", "elsa@acme.lan"} {
		if strings.Contains(html, absent) {
			t.Errorf("%s figure dans la liste alors que sa portée est conforme : sa place est dans la fiche", absent)
		}
	}
	if !strings.Contains(html, "dora@acme.lan") || !strings.Contains(html, "2 écart(s)") {
		t.Error("le compte en écart ne remonte pas sous sa machine : PC-02 s'afficherait conforme")
	}
	if !strings.Contains(html, "3 ok") {
		t.Error("l'état des comptes de PC-01 (« 3 ok ») n'est pas affiché")
	}
	if !strings.Contains(html, `<span class="badge badge-danger">1 en écart sur 2</span>`) {
		t.Error("l'état des comptes de PC-02 n'est pas mis en avant")
	}
	// Les comptes de PC-01 n'ont pas rapporté depuis hier : la machine, elle, si.
	if strings.Contains(html, "en retard") {
		t.Error("une machine est « en retard » parce que des personnes ne sont plus connectées")
	}
	if !strings.Contains(html, "2 machine(s) : 1 avec écarts.") {
		t.Errorf("résumé inattendu ; la page ne porte pas « 2 machine(s) : 1 avec écarts. »")
	}
	if !strings.Contains(html, "2 machine(s) sur 2 suivie(s)") {
		t.Error("le pied de tableau ne compte pas des machines")
	}
}
