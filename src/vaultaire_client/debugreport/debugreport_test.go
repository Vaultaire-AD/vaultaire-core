package debugreport

import (
	"strings"
	"testing"
	"time"
)

func TestAnalyserWho(t *testing.T) {
	s := AnalyserWho("alice@acme.lan pts/0        2026-09-22 16:58 (10.0.0.42)\nroot     tty1         2026-09-22 08:01\n\n")
	if len(s) != 2 {
		t.Fatalf("%+v", s)
	}
	if s[0].Utilisateur != "alice@acme.lan" || s[0].Terminal != "pts/0" || s[0].Depuis != "2026-09-22 16:58" || s[0].Origine != "(10.0.0.42)" {
		t.Fatalf("%+v", s[0])
	}
	if s[1].Origine != "" || s[1].Depuis != "2026-09-22 08:01" {
		t.Fatalf("%+v", s[1])
	}
}

func etatExemple() Etat {
	instant := time.Date(2026, 9, 22, 17, 4, 0, 0, time.Local)
	e := Etat{Instant: instant}
	e.Agent = Agent{ComputeurID: "c-42", Version: "2.2.0+gabc (2026-09-22)", Uptime: 2 * time.Hour, Intervalle: time.Minute}
	e.Connexion = Connexion{Supervise: true, Adresse: "10.0.0.11:6666", Hostname: "core-b", Role: "core",
		Depuis: instant.Add(-90 * time.Minute), EtatTunnel: "authentifié", Etablissements: 2, NbEmpreintes: 1}
	e.Noeuds = []NoeudOrdre{
		{Adresse: "10.0.1.5:6666", Role: "proxy", Hostname: "proxy-lyon", Source: "appris (04_04)"},
		{Adresse: "10.0.0.11:6666", Role: "core", Hostname: "core-b", Source: "appris, persisté", Courant: true},
		{Adresse: "10.0.0.10:6666", Source: "installation"},
	}
	e.Sessions = []Session{{SessionID: "abcdef123456", Username: "vaultaire", Statut: "authentifiée",
		Distant: "10.0.0.11:6666", Creee: instant.Add(-90 * time.Minute), Vue: instant.Add(-10 * time.Second), Sure: true, Cle: true}}
	e.SessionsLocales = []SessionLocale{{Utilisateur: "alice@acme.lan", Terminal: "pts/0", Depuis: "2026-09-22 16:58", Vaultaire: true}}
	e.Comptes = []Compte{{Nom: "alice@acme.lan", UID: 5001, Connecte: true}}
	e.GPO.Machine = &ScopeGPO{Empreinte: "1a2b3c4d", Version: 3, AppliqueeLe: "2026-09-22T16:00:00Z", Statut: "applied", Modules: 4, Audit: 1}
	e.GPO.Cycles = []CycleGPO{{Scope: "machine", Debut: instant.Add(-time.Hour), Resume: "statut=partial", Echecs: []string{"dns_resolver (dns) : échec simulé"}}}
	e.Alertes = alertes(e)
	return e
}

func TestLeRapportPorteSonEnTeteEtSesSections(t *testing.T) {
	r := Construire(etatExemple())
	for _, attendu := range []string{
		"Rapport de debug", "22/09/2026 - 17h04",
		"Connexion au cluster", "10.0.0.11:6666 (core-b, core)",
		"Nœuds dans l'ordre d'essai", "▶  2. 10.0.0.11:6666",
		"Sessions Ducky (1)", "abcdef12", "authentifiée",
		"Sessions ouvertes sur la machine (1)", "alice@acme.lan",
		"Comptes Vaultaire provisionnés (1)", "uid=5001",
		"GPO", "empreinte 1a2b3c4d", "dont 1 en mode audit", "✗ dns_resolver",
		"Points d'attention", "module(s) en échec",
	} {
		if !strings.Contains(r, attendu) {
			t.Errorf("%q absent du rapport :\n%s", attendu, r)
		}
	}
	// Aucune clé : seulement sa présence.
	if strings.Contains(r, "SessionKey") {
		t.Error("le rapport mentionne une clé de session")
	}
}

func TestUnAgentDeconnecteLeDitEnTete(t *testing.T) {
	e := etatExemple()
	e.Connexion.Adresse = ""
	e.Connexion.EtatTunnel = "ABSENT ou non authentifié"
	e.Connexion.NbEmpreintes = 0
	e.Alertes = alertes(e)
	r := Construire(e)
	for _, attendu := range []string{"AUCUN — tunnel non établi", "aucune session machine authentifiée", "aucune empreinte de confiance"} {
		if !strings.Contains(r, attendu) {
			t.Errorf("%q absent :\n%s", attendu, r)
		}
	}
}

func TestLaCollecteNeBloquePas(t *testing.T) {
	ancien := lireSessionsLocales
	defer func() { lireSessionsLocales = ancien }()
	lireSessionsLocales = func() ([]SessionLocale, error) { return nil, nil }
	fini := make(chan string, 1)
	go func() { fini <- Construire(Collecter(time.Now(), time.Minute)) }()
	select {
	case r := <-fini:
		if !strings.Contains(r, "Rapport de debug") {
			t.Fatal(r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("la collecte a bloqué (attente d'une session ?)")
	}
}
