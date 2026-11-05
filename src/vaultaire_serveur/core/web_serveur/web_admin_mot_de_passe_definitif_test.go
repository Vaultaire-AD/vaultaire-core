package webserveur

import (
	"bytes"
	"html/template"
	"path/filepath"
	"regexp"
	"testing"

	"vaultaire/core/storage"
)

// TO-DO 144 : les deux formulaires qui posent un mot de passe — création d'un
// compte et changement depuis sa fiche — proposent « définitif ». Et, envoyés
// sans rien toucher, ils restent PROVISOIRES : c'est le cas d'une personne,
// le plus courant, et le seul sûr par défaut.
func TestLesFormulairesDeMotDePasseProposentDefinitifEtRestentProvisoiresParDefaut(t *testing.T) {
	rendre := func(page string, data any) string {
		t.Helper()
		tmpl, err := template.ParseFiles(
			filepath.Join(cheminGabarits, "admin_sidebar.html"),
			filepath.Join(cheminGabarits, page))
		if err != nil {
			t.Fatalf("%s : analyse : %v", page, err)
		}
		var b bytes.Buffer
		if err := tmpl.ExecuteTemplate(&b, page, data); err != nil {
			t.Fatalf("%s : exécution : %v", page, err)
		}
		return b.String()
	}
	verifier := func(page, html, action string) {
		t.Helper()
		form := regexp.MustCompile(`(?s)<form[^>]*>(?:(?:[^<]|<[^/]|</[^f])*?)name="action" value="` +
			action + `".*?</form>`).FindString(html)
		if form == "" {
			t.Fatalf("%s : formulaire %s introuvable", page, action)
		}
		sel := regexp.MustCompile(`(?s)<select name="temporary">.*?</select>`).FindString(form)
		if sel == "" {
			t.Fatalf("%s : le formulaire %s n'a pas de liste « temporary »", page, action)
		}
		opts := regexp.MustCompile(`<option value="(\w+)"( selected)?`).FindAllStringSubmatch(sel, -1)
		if len(opts) != 2 || opts[0][1] != "oui" || opts[0][2] == "" || opts[1][1] != "non" || opts[1][2] != "" {
			t.Fatalf("%s : options %q — attendu « oui » présélectionné puis « non »", page, opts)
		}
	}

	liste := rendre("admin_users.html", struct {
		Username  string
		Users     []storage.GetUsers
		Message   string
		Error     string
		DnsEnable bool
		Section   string
	}{Username: "admin", Section: "users"})
	verifier("admin_users.html", liste, "create_user")

	fiche := rendre("admin_user_detail.html", map[string]any{
		"Username": "admin", "Section": "users",
		"User": map[string]any{"Username": "svc_keycloak"},
	})
	verifier("admin_user_detail.html", fiche, "change_password")
}
