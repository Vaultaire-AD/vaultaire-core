package webserveur

import (
	"bytes"
	"html/template"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	act "vaultaire/core/action"
)

// L'accueil de l'administration porte le réglage du journal de détail, par
// sous-système (TO-DO 145).
//
// Un gabarit ne se vérifie qu'en l'EXÉCUTANT : un champ mal nommé passe la
// compilation et l'analyse, et ne casse qu'à la première visite — avec une
// page tronquée au milieu du tableau.
func TestLAccueilAdminSeRend(t *testing.T) {
	tmpl, err := template.ParseFiles(
		filepath.Join(cheminGabarits, "admin_sidebar.html"),
		filepath.Join(cheminGabarits, "admin.html"))
	if err != nil {
		t.Fatalf("analyse du gabarit : %v", err)
	}

	data := donneesAccueilAdmin{Username: "alice", Section: "dashboard", Debug: true,
		Detail: []act.DetailDeSousSysteme{
			{Nom: "ldap", Regle: "trace", Effectif: "trace"},
			{Nom: "ducky", Regle: "off", Effectif: "off"},
			{Nom: "gpo", Effectif: "debug"}, // suit le mode debug
		}}

	var page bytes.Buffer
	if err := tmpl.ExecuteTemplate(&page, "admin.html", data); err != nil {
		t.Fatalf("exécution du gabarit : %v", err)
	}
	html := page.String()

	// Un formulaire par sous-système, et chacun présélectionne son réglage :
	// soumettre sans rien toucher ne doit rien changer.
	choisi := func(sous string) string {
		bloc := regexp.MustCompile(`(?s)name="sous_systeme" value="` + sous + `".*?</select>`).FindString(html)
		if bloc == "" {
			t.Fatalf("aucun formulaire pour le sous-système %s", sous)
		}
		m := regexp.MustCompile(`<option value="(\w+)"\s+selected`).FindAllStringSubmatch(bloc, -1)
		if len(m) != 1 {
			t.Fatalf("%s : %d option(s) présélectionnée(s), attendu une seule", sous, len(m))
		}
		return m[0][1]
	}
	for sous, attendu := range map[string]string{"ldap": "trace", "ducky": "off", "gpo": "defaut"} {
		if got := choisi(sous); got != attendu {
			t.Errorf("%s : option présélectionnée %q, attendu %q — le formulaire soumis tel "+
				"quel changerait le réglage", sous, got, attendu)
		}
	}

	// Les formulaires de détail portent la MÊME action que le réglage général :
	// c'est elle que le pont connaît, et c'est son champ `sous_systeme` qui les
	// distingue.
	if n := strings.Count(html, `name="action" value="set_debug"`); n != 4 {
		t.Errorf("%d formulaire(s) set_debug, attendu 4 : le réglage général et trois sous-systèmes", n)
	}
	if !strings.Contains(html, "suit le mode debug") {
		t.Error("un sous-système sans réglage propre ne dit pas qu'il suit le mode debug")
	}
}
