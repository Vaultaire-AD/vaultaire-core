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

// TO-DO 192 : « Exécuter une commande » ouvre la page, son résultat juste
// dessous, et le debug vient après — c'est l'usage courant qui passe en tête.
func TestLaCommandeOuvreLeTableauDeBord(t *testing.T) {
	tmpl, err := template.ParseFiles(
		filepath.Join(cheminGabarits, "admin_sidebar.html"),
		filepath.Join(cheminGabarits, "admin.html"))
	if err != nil {
		t.Fatalf("analyse du gabarit : %v", err)
	}
	var page bytes.Buffer
	if err := tmpl.ExecuteTemplate(&page, "admin.html",
		donneesAccueilAdmin{Username: "alice", Section: "dashboard"}); err != nil {
		t.Fatalf("exécution du gabarit : %v", err)
	}
	html := page.String()
	commande := strings.Index(html, "<h2>Exécuter une commande</h2>")
	resultat := strings.Index(html, "<h2>Résultat</h2>")
	debug := strings.Index(html, "<h2>Mode debug</h2>")
	if commande < 0 || resultat < 0 || debug < 0 {
		t.Fatalf("section absente : commande %d, résultat %d, debug %d", commande, resultat, debug)
	}
	if !(commande < resultat && resultat < debug) {
		t.Errorf("ordre des sections : commande %d, résultat %d, debug %d — attendu commande, "+
			"résultat, puis debug", commande, resultat, debug)
	}
	if h2 := strings.Index(html, "<h2>"); h2 != commande {
		t.Errorf("la première section n'est pas « Exécuter une commande »")
	}
}
