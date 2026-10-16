package webserveur

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"

	act "vaultaire/core/action"
	"vaultaire/core/parcversion"
	"vaultaire/core/storage"
)

// La colonne VERSION de la liste des clients — TO-DO 111.
//
// La structure reprend celle d'AdminClientsHandler, champ pour champ : c'est
// une structure anonyme, que le test des champs des gabarits n'atteint pas.
func rendreLaListeDesClients(t *testing.T, versions map[string]*act.LigneAgent) string {
	t.Helper()
	data := struct {
		Clients        []storage.GetClientsByPermission
		Message        string
		Error          string
		Username       string
		DnsEnable      bool
		Section        string
		ArchiveLien    string
		ArchiveMachine string
		ArchiveSysteme string
		Versions       map[string]*act.LigneAgent
	}{
		Username: "root", Section: "clients", Versions: versions,
		Clients: []storage.GetClientsByPermission{
			{ID: 1, LogicielType: "vaultaire_client", ComputeurID: "id-a", Hostname: "pilote-1",
				OS: "Rocky", AgentVersion: "2.3.0+gabc (2026-10-01)"},
			{ID: 2, LogicielType: "vaultaire_client", ComputeurID: "id-b", Hostname: "poste-b",
				OS: "Rocky", AgentVersion: "2.4.0"},
			{ID: 3, LogicielType: "vaultaire_proxy", ComputeurID: "id-p", Hostname: "proxy",
				OS: "Rocky", AgentVersion: "2.3.0 (build local)"},
		},
	}
	tmpl, err := template.ParseFiles(
		filepath.Join(cheminGabarits, "admin_sidebar.html"),
		filepath.Join(cheminGabarits, "admin_clients.html"))
	if err != nil {
		t.Fatalf("analyse du gabarit : %v", err)
	}
	var page bytes.Buffer
	if err := tmpl.ExecuteTemplate(&page, "admin_clients.html", data); err != nil {
		t.Fatalf("exécution du gabarit : %v", err)
	}
	return page.String()
}

func TestLaListeDesClientsMontreLEcart(t *testing.T) {
	cible := parcversion.Attendue{Definie: true, Version: parcversion.V(2, 4, 0),
		Source: parcversion.SourceGroupe, Groupe: "pilote"}
	page := rendreLaListeDesClients(t, map[string]*act.LigneAgent{
		"id-a": {ComputeurID: "id-a", VersionLisible: "2.3.0", Attendue: cible, Etat: parcversion.EtatEnRetard},
		"id-b": {ComputeurID: "id-b", VersionLisible: "2.4.0", Attendue: cible, Etat: parcversion.EtatAJour},
	})
	for _, morceau := range []string{
		"<th>Version</th>",
		`<span class="badge badge-danger" title="Attendue : 2.4.0 (groupe pilote)">en retard · 2.4.0</span>`,
		`<span class="badge" title="Attendue : 2.4.0 (groupe pilote)">à jour · 2.4.0</span>`,
		// Un service n'a pas de version attendue : sa version déclarée, brute.
		"2.3.0 (build local)",
		"vlt agent",
	} {
		if !strings.Contains(page, morceau) {
			t.Errorf("page sans %q", morceau)
		}
	}
}

// Sans read:log, la colonne reste : la version déclarée, sans écart.
func TestLaListeDesClientsSansLesCibles(t *testing.T) {
	page := rendreLaListeDesClients(t, nil)
	if !strings.Contains(page, "gabc (2026-10-01)") { // « + » est échappé par html/template
		t.Error("la version déclarée manque quand les cibles ne sont pas lisibles")
	}
	if strings.Contains(page, "badge-danger") || strings.Contains(page, "vlt agent") {
		t.Error("un écart est montré sans que les cibles aient été lues")
	}
}
