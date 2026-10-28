package webserveur

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dbgpo "vaultaire/core/database/db_gpo"
)

// TO-DO 222 : la fiche d'une machine montre les conflits entre GPO — des
// modules qu'elle n'a pas reçus, que rien d'autre sur la page ne trahirait.
func TestLaFicheMontreLesConflitsEntreGPO(t *testing.T) {
	tmpl, err := template.ParseFiles(
		filepath.Join(cheminGabarits, "admin_sidebar.html"),
		filepath.Join(cheminGabarits, "admin_gpo_compliance_detail.html"))
	if err != nil {
		t.Fatalf("analyse du gabarit : %v", err)
	}
	data := map[string]any{
		"Username": "root", "Section": "conformite", "Machine": "web01",
		"Conflits": []dbgpo.ConflitGPO{{ComputeurID: "web01", Scope: "machine", SeenAt: time.Now(),
			Detail: `le service chronyd est réglé à la fois par la GPO "a" et par la GPO "b"`}},
	}
	var page bytes.Buffer
	if err := tmpl.ExecuteTemplate(&page, "admin_gpo_compliance_detail.html", data); err != nil {
		t.Fatalf("exécution du gabarit : %v", err)
	}
	html := page.String()
	for _, m := range []string{"Conflits entre GPO", "le service chronyd", "pas</strong> livrés"} {
		if !strings.Contains(html, m) {
			t.Errorf("page sans %q", m)
		}
	}
}
