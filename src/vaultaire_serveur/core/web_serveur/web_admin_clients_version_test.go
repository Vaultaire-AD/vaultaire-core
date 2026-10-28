package webserveur

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	act "vaultaire/core/action"
	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/parcversion"
	"vaultaire/core/storage"
)

// La colonne VERSION de la liste des clients — TO-DO 111.
//
// La structure reprend celle d'AdminClientsHandler, champ pour champ : c'est
// une structure anonyme, que le test des champs des gabarits n'atteint pas.
func rendreLaListeDesClients(t *testing.T, relancer bool, versions map[string]*act.LigneAgent) string {
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
		PeutRelancer   bool
	}{
		Username: "root", Section: "clients", Versions: versions, PeutRelancer: relancer,
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
	page := rendreLaListeDesClients(t, false, map[string]*act.LigneAgent{
		"id-a": {ComputeurID: "id-a", VersionLisible: "2.3.0", Attendue: cible, Etat: parcversion.EtatEnRetard},
		"id-b": {ComputeurID: "id-b", VersionLisible: "2.4.0", Attendue: cible, Etat: parcversion.EtatAJour,
			CompteRendu: dbclients.CompteRendu{Version: "2.4.0", Resultat: "installe"}},
	})
	for _, morceau := range []string{
		"<th>Version</th>",
		`<span class="badge badge-danger" title="Attendue : 2.4.0 (groupe pilote)">en retard · 2.4.0</span>`,
		`<span class="badge" title="Attendue : 2.4.0 (groupe pilote)">à jour · 2.4.0</span>`,
		// Un service n'a pas de version attendue : sa version déclarée, brute.
		"2.3.0 (build local)",
		"vlt agent",
		"dernier compte rendu : 2.4.0 installe",
	} {
		if !strings.Contains(page, morceau) {
			t.Errorf("page sans %q", morceau)
		}
	}
}

// Sans read:log, la colonne reste : la version déclarée, sans écart.
func TestLaListeDesClientsSansLesCibles(t *testing.T) {
	page := rendreLaListeDesClients(t, false, nil)
	if !strings.Contains(page, "gabc (2026-10-01)") { // « + » est échappé par html/template
		t.Error("la version déclarée manque quand les cibles ne sont pas lisibles")
	}
	if strings.Contains(page, "badge-danger") || strings.Contains(page, "vlt agent") {
		t.Error("un écart est montré sans que les cibles aient été lues")
	}
}

// TO-DO 205 : la configuration système sous la version, et le bouton
// « Relancer » — seulement pour un agent en retard, et seulement à qui porte
// write:server sur tout le parc.
func TestLaListeDesClientsRelanceEtConfiguration(t *testing.T) {
	cible := parcversion.Attendue{Definie: true, Version: parcversion.V(2, 4, 0),
		Source: parcversion.SourceGroupe, Groupe: "pilote"}
	versions := map[string]*act.LigneAgent{
		"id-a": {ComputeurID: "id-a", VersionLisible: "2.3.0", Attendue: cible, Etat: parcversion.EtatEnRetard,
			CompteRendu:   dbclients.CompteRendu{Version: "2.4.0", Resultat: "echec", Motif: "revenue en arrière : tunnel"},
			Configuration: dbclients.Configuration{Etat: "ecart", Motif: "refusé : ssh/sshd_config : sshd -t refuse"}},
		"id-b": {ComputeurID: "id-b", VersionLisible: "2.4.0", Attendue: cible, Etat: parcversion.EtatAJour,
			Configuration: dbclients.Configuration{Etat: "reconciliee", Motif: "écrit : ssh/sshd_config v0→v1"}},
	}
	page := rendreLaListeDesClients(t, true, versions)
	for _, morceau := range []string{
		`<span class="badge badge-danger" title="refusé : ssh/sshd_config : sshd -t refuse">configuration : écart</span>`,
		`<span class="badge" title="écrit : ssh/sshd_config v0→v1">configuration : réconciliée</span>`,
		`<input type="hidden" name="action" value="relaunch_agent_update">`,
		`<input type="hidden" name="computeur_id" value="id-a">`,
		"Relancer la mise à jour de id-a vers 2.4.0 ?",
	} {
		if !strings.Contains(page, morceau) {
			t.Errorf("page sans %q", morceau)
		}
	}
	// Un seul bouton : id-b est à jour, le proxy n'est pas un agent.
	if n := strings.Count(page, `value="relaunch_agent_update"`); n != 1 {
		t.Errorf("%d bouton(s) Relancer, 1 attendu", n)
	}
	if strings.Contains(page, "Relancer la mise à jour de id-b") {
		t.Error("bouton sur une machine à jour")
	}

	// Sans write:server global : la configuration reste visible, le bouton non.
	sans := rendreLaListeDesClients(t, false, versions)
	if strings.Contains(sans, "relaunch_agent_update") || !strings.Contains(sans, "configuration : écart") {
		t.Error("bouton montré sans le droit, ou configuration masquée")
	}
}

// Le bouton « Relancer » mène à agent.update, et le registre en garde
// l'accès : sans write:server, refus — jamais d'ordre poussé par la page.
func TestRelancerPasseParLeRegistre(t *testing.T) {
	if nom, ok := ActionDuRegistrePour("relaunch_agent_update"); !ok || nom != "agent.update" {
		t.Fatalf("%q %v", nom, ok)
	}
	catalogueCharge()
	r := httptest.NewRequest(http.MethodPost, "/admin/clients",
		strings.NewReader("action=relaunch_agent_update&computeur_id=id-a"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, traite, err := ExecuterActionFormulaire(r, "delegue", nil)
	var refus *act.ErrRefusee
	if !traite || !errors.As(err, &refus) || refus.Action != "agent.update" || refus.Cle != "write:server" {
		t.Fatalf("traité=%v, %v", traite, err)
	}
}
