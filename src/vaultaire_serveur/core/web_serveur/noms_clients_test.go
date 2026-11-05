package webserveur

import (
	"bytes"
	"html/template"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"vaultaire/core/storage"
)

// TO-DO 191 : le portail fait choisir les clients d'un groupe par leur nom, pas
// par leur seul identifiant.

func TestNomsDesClients(t *testing.T) {
	noms := NomsDesClients([]storage.GetClientsByPermission{
		{ComputeurID: "a1b2", Hostname: "web01"},
		{ComputeurID: "c3d4", Hostname: ""}, // inventaire jamais reçu
	})
	if noms["a1b2"] != "web01" {
		t.Errorf("a1b2 -> %q, attendu web01", noms["a1b2"])
	}
	if _, ok := noms["c3d4"]; ok {
		t.Error("une machine sans nom a une entrée : le gabarit afficherait « — id »")
	}
}

func TestLaFicheDuGroupeNommeSesClients(t *testing.T) {
	tmpl, err := template.ParseFiles(
		filepath.Join(cheminGabarits, "admin_sidebar.html"),
		filepath.Join(cheminGabarits, "admin_group_detail.html"))
	if err != nil {
		t.Fatalf("analyse du gabarit : %v", err)
	}
	tous := []storage.GetClientsByPermission{
		{ComputeurID: "a1b2", Hostname: "web01"},
		{ComputeurID: "c3d4"},
	}
	var page bytes.Buffer
	err = tmpl.ExecuteTemplate(&page, "admin_group_detail.html", map[string]any{
		"Group": "Infra", "Clients": []string{"a1b2", "c3d4"},
		"AllClients": tous, "NomsClients": NomsDesClients(tous), "Section": "groups",
	})
	if err != nil {
		t.Fatalf("exécution du gabarit : %v", err)
	}
	html := page.String()

	// Ajouter : nom et identifiant à l'écran, l'identifiant seul en valeur.
	if !strings.Contains(html, `<option value="a1b2">web01 — a1b2</option>`) {
		t.Errorf("l'option d'ajout de a1b2 ne porte pas « web01 — a1b2 »")
	}
	// Sans nom connu : l'identifiant seul, sans tiret pendant.
	if !strings.Contains(html, `<option value="c3d4">c3d4</option>`) {
		t.Errorf("une machine sans nom n'est pas affichée par son seul identifiant")
	}
	// Retirer : la même chose, à partir des identifiants du groupe.
	retirer := regexp.MustCompile(`(?s)name="action" value="remove_client".*?</select>`).FindString(html)
	if !strings.Contains(retirer, `<option value="a1b2">web01 — a1b2</option>`) {
		t.Errorf("le formulaire de retrait ne nomme pas a1b2 :\n%s", retirer)
	}
	// La liste des clients du groupe.
	if !strings.Contains(html, `web01 <span class="muted small">a1b2</span>`) {
		t.Errorf("la liste des clients du groupe ne porte pas le nom")
	}
}
