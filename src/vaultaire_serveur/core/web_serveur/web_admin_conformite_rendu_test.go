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

// La page Conformité fait ressortir une portée jamais vérifiée (TO-DO 135).
//
// « non vérifié » s'affichait en texte nu, entre deux « ok » : la cellule se
// lisait comme une valeur parmi d'autres, et le résumé concluait « toutes à
// jour ». C'est ce qui a laissé le scope utilisateur sans aucune vérification
// pendant des semaines sans que personne ne s'en étonne.
//
// Le gabarit est EXÉCUTÉ : un champ mal nommé passe la compilation et ne casse
// qu'à la première visite.
func TestLaPageConformiteFaitRessortirLeNonVerifie(t *testing.T) {
	maintenant := time.Now()
	verifiee := sql.NullTime{Time: maintenant, Valid: true}
	rows := []dbgpo.ComplianceRow{
		{ComputeurID: "PC-01", Scope: "machine", Status: "applied", ModulesTotal: 3,
			ReportedAt: maintenant, DriftAt: verifiee, DriftChecked: 7},
		{ComputeurID: "PC-01", Scope: "user", TargetUser: "alice@acme.lan", Status: "applied",
			ModulesTotal: 4, ReportedAt: maintenant},
	}

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
	}{Username: "root", Section: "conformite", Total: len(rows),
		Resume: dbgpo.ResumerParc(rows, maintenant).Lisible()}
	for _, r := range rows {
		data.Lignes = append(data.Lignes, vueDeLigne(r, maintenant))
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
	html := page.String()

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
}
