package action

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/miseajour"
	"vaultaire/core/parcversion"
	miseajourmanager "vaultaire/ducky-network/miseajour_manager"
)

// parcDEssai : un pilote en avance, un groupe général sur le défaut du parc,
// un poste figé, un poste qui n'a jamais déclaré sa version.
func parcDEssai(t *testing.T, parc string) {
	t.Helper()
	reveil := reveillerLaPoussee
	t.Cleanup(func() { reveillerLaPoussee = reveil })
	reveillerLaPoussee = func() {}
	ancienne := lireCibles
	t.Cleanup(func() { lireCibles = ancienne })
	lireCibles = sourceDesCibles{
		agents: func() ([]dbclients.AgentEtCibles, error) {
			return []dbclients.AgentEtCibles{
				{ComputeurID: "id-a", Hostname: "pilote-1", Declaree: "2.3.0+gabc (2026-10-01)",
					Groupes: map[string]string{"pilote": "2.4.0", "general": ""}},
				{ComputeurID: "id-b", Hostname: "poste-b", Declaree: "2.3.0",
					Groupes: map[string]string{"general": ""}},
				{ComputeurID: "id-c", Hostname: "fragile", Declaree: "2.3.0", Derogation: "2.2.0",
					Groupes: map[string]string{"pilote": "2.4.0"}},
				{ComputeurID: "id-d", Hostname: "", Declaree: "",
					Groupes: map[string]string{}},
			}, nil
		},
		parc: func() (string, bool, error) { return parc, parc != "", nil },
		groupes: func() ([]dbclients.CibleGroupe, error) {
			return []dbclients.CibleGroupe{{Groupe: "pilote", Version: "2.4.0"}}, nil
		},
		groupeExiste: func(g string) (bool, error) { return g == "pilote" || g == "general", nil },
	}
}

func TestVueAgentsResoutEtSitue(t *testing.T) {
	parcDEssai(t, "2.3.0")
	vue, err := construireVue("")
	if err != nil {
		t.Fatal(err)
	}
	attendu := map[string]struct {
		etat   parcversion.Etat
		source parcversion.Source
	}{
		"id-a": {parcversion.EtatEnRetard, parcversion.SourceGroupe},
		"id-b": {parcversion.EtatAJour, parcversion.SourceParc},
		"id-c": {parcversion.EtatEnAvance, parcversion.SourceMachine},
		"id-d": {parcversion.EtatInconnue, parcversion.SourceParc},
	}
	for _, l := range vue.Machines {
		a := attendu[l.ComputeurID]
		if l.Etat != a.etat || l.Attendue.Source != a.source {
			t.Errorf("%s : %s / %s, attendu %s / %s", l.ComputeurID,
				l.Etat, l.Attendue.Source, a.etat, a.source)
		}
	}
	// Ce qui demande un regard d'abord.
	if vue.Machines[0].Etat != parcversion.EtatEnRetard || vue.Machines[1].Etat != parcversion.EtatInconnue {
		t.Errorf("ordre : %s puis %s", vue.Machines[0].Etat, vue.Machines[1].Etat)
	}
	if vue.Machines[1].Nom() != "id-d" {
		t.Errorf("une machine sans nom d'hôte se nomme par son identifiant : %q", vue.Machines[1].Nom())
	}
	if !strings.Contains(vue.Bilan(), "4 agent(s) : 1 en retard, 1 inconnue, 1 en avance, 1 à jour") {
		t.Errorf("bilan : %q", vue.Bilan())
	}
}

func TestVueAgentsSansCibleNulPart(t *testing.T) {
	parcDEssai(t, "")
	vue, err := construireVue("general")
	if err != nil {
		t.Fatal(err)
	}
	// general n'a pas de cible, le parc non plus : poste-b ne bougera pas.
	// pilote-1, lui, suit le pilote.
	for _, l := range vue.Machines {
		switch l.ComputeurID {
		case "id-b":
			if l.Etat != parcversion.EtatSansCible {
				t.Errorf("poste-b : %s", l.Etat)
			}
		case "id-a":
			if l.Etat != parcversion.EtatEnRetard {
				t.Errorf("pilote-1 : %s", l.Etat)
			}
		default:
			t.Errorf("%s n'est pas dans general", l.ComputeurID)
		}
	}
}

func TestVueAgentsGroupeInconnu(t *testing.T) {
	parcDEssai(t, "")
	if _, err := construireVue("pilot"); err == nil || !strings.Contains(err.Error(), "introuvable") {
		t.Errorf("groupe mal tapé : %v", err)
	}
}

// Une base qui flanche ne doit pas se lire « aucune cible » : ce serait
// mentir sur ce qui va se passer.
func TestVueAgentsNeMasquePasUnePanne(t *testing.T) {
	parcDEssai(t, "2.3.0")
	lireCibles.parc = func() (string, bool, error) { return "", false, errors.New("base injoignable") }
	if _, err := construireVue(""); err == nil {
		t.Error("panne de lecture du réglage rendue comme une vue")
	}
	parcDEssai(t, "2.3.0")
	lireCibles.agents = func() ([]dbclients.AgentEtCibles, error) { return nil, errors.New("base injoignable") }
	if _, err := construireVue(""); err == nil {
		t.Error("panne de lecture des machines rendue comme une vue")
	}
}

func TestVueAgentsDefautIllisible(t *testing.T) {
	parcDEssai(t, "2.3")
	vue, err := construireVue("")
	if err != nil {
		t.Fatal(err)
	}
	if vue.Parc != "" || vue.ParcIllisible != "2.3" {
		t.Errorf("défaut illisible : Parc=%q ParcIllisible=%q", vue.Parc, vue.ParcIllisible)
	}
	for _, l := range vue.Machines {
		if l.ComputeurID == "id-b" && l.Etat != parcversion.EtatSansCible {
			t.Errorf("un défaut illisible ne doit rien déclencher : %s", l.Etat)
		}
	}
}

func TestVersionSaisie(t *testing.T) {
	if v, err := versionSaisie(Params{"version": "v2.4.0"}); err != nil || v != "2.4.0" {
		t.Errorf("v2.4.0 : %q, %v", v, err)
	}
	for _, eff := range []string{"none", "--none"} {
		if v, err := versionSaisie(Params{"version": eff}); err != nil || v != "" {
			t.Errorf("%s : %q, %v", eff, v, err)
		}
	}
	for _, mauvaise := range []string{"", "2.4", "2.4.0-rc1", "latest"} {
		if _, err := versionSaisie(Params{"version": mauvaise}); err == nil {
			t.Errorf("%q acceptée", mauvaise)
		}
	}
}

func TestPoserUneCibleDeGroupe(t *testing.T) {
	parcDEssai(t, "2.3.0")
	ancienne := ecrireCibleGroupe
	t.Cleanup(func() { ecrireCibleGroupe = ancienne })
	var ecrit string
	ecrireCibleGroupe = func(g, v string) error {
		if g == "absent" {
			return fmt.Errorf("groupe %q %w", g, dbclients.ErrIntrouvable)
		}
		ecrit = g + "=" + v
		return nil
	}

	res, err := definirCibleAgents(Appelant{Username: "vaultaire"}, Params{"group": "pilote", "version": "v2.4.0"})
	if err != nil {
		t.Fatal(err)
	}
	if ecrit != "pilote=2.4.0" {
		t.Errorf("écrit : %q", ecrit)
	}
	// pilote-1 suit le pilote et est en retard ; fragile est dans le pilote mais
	// figé par sa dérogation.
	for _, morceau := range []string{"2.4.0", "1 agent(s) la suivent, dont 1 à mettre à jour",
		"1 autre(s) machine(s) du groupe", noteDeroule} {
		if !strings.Contains(res.Message, morceau) {
			t.Errorf("message sans %q :\n%s", morceau, res.Message)
		}
	}

	if _, err := definirCibleAgents(Appelant{}, Params{"group": "absent", "version": "2.4.0"}); err == nil ||
		!strings.Contains(err.Error(), "introuvable") {
		t.Errorf("groupe inconnu : %v", err)
	}

	res, err = definirCibleAgents(Appelant{}, Params{"group": "pilote", "version": "none"})
	if err != nil || ecrit != "pilote=" || strings.Contains(res.Message, noteDeroule) {
		t.Errorf("effacement : %q, %v, %q", ecrit, err, res.Message)
	}
}

func TestPoserLeDefautDuParc(t *testing.T) {
	parcDEssai(t, "2.3.0")
	ancienne := ecrireCibleParc
	t.Cleanup(func() { ecrireCibleParc = ancienne })
	var ecrit, auteur string
	ecrireCibleParc = func(v, a string) error { ecrit, auteur = v, a; return nil }

	res, err := definirCibleAgents(Appelant{Username: "alice"}, Params{"version": "2.3.0"})
	if err != nil {
		t.Fatal(err)
	}
	if ecrit != "2.3.0" || auteur != "alice" {
		t.Errorf("écrit %q par %q", ecrit, auteur)
	}
	if res.Cible != "version attendue du parc" {
		t.Errorf("cible d'audit : %q", res.Cible)
	}
	// poste-b et la machine sans nom suivent le parc ; les deux autres non.
	if !strings.Contains(res.Message, "2 agent(s) la suivent, dont 1 à mettre à jour") ||
		!strings.Contains(res.Message, "2 autre(s) suivent la cible d'un groupe ou une dérogation") {
		t.Errorf("message :\n%s", res.Message)
	}
}

func TestDeroger(t *testing.T) {
	parcDEssai(t, "2.3.0")
	ancienne := ecrireDerogation
	t.Cleanup(func() { ecrireDerogation = ancienne })
	var retrograde bool
	ecrireDerogation = func(id, v string, r bool) error {
		if id != "id-c" {
			return fmt.Errorf("machine %q %w", id, dbclients.ErrIntrouvable)
		}
		retrograde = r
		return nil
	}
	res, err := definirDerogationAgent(Appelant{}, Params{"computeur_id": "id-c", "version": "2.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Message, "id-c attend 2.2.0") || !strings.Contains(res.Message, "en avance") {
		t.Errorf("message :\n%s", res.Message)
	}
	if _, err := definirDerogationAgent(Appelant{}, Params{"computeur_id": "x", "version": "2.2.0"}); err == nil ||
		!strings.Contains(err.Error(), "introuvable") {
		t.Errorf("machine inconnue : %v", err)
	}
	if _, err := definirDerogationAgent(Appelant{}, Params{"version": "2.2.0"}); err == nil {
		t.Error("machine manquante acceptée")
	}
	if retrograde {
		t.Error("rétrogradation posée sans --downgrade")
	}

	// TO-DO 204 : --downgrade, durable.
	res, err = definirDerogationAgent(Appelant{}, Params{"computeur_id": "id-c", "version": "2.2.0", "downgrade": "yes"})
	if err != nil || !retrograde || !strings.Contains(res.Message, "Rétrogradation AUTORISÉE") {
		t.Fatalf("%v %v %q", err, retrograde, res.Message)
	}
	if _, err := definirDerogationAgent(Appelant{}, Params{"computeur_id": "id-c", "version": "none", "downgrade": "yes"}); err == nil {
		t.Error("--downgrade sans version accepté")
	}
}

func TestRelancerMiseAJour(t *testing.T) {
	avant := relancer
	t.Cleanup(func() { relancer = avant })

	cas := []struct {
		r       miseajourmanager.Relance
		err     error
		retro   string
		attendu string
		echec   bool
	}{
		{r: miseajourmanager.Relance{Ordre: &miseajour.Ordre{Version: "2.4.0", Depot: "releases"}, Envoyee: true},
			attendu: "Ordre 2.4.0 (dépôt releases) poussé à poste-1"},
		{r: miseajourmanager.Relance{Ordre: &miseajour.Ordre{Version: "2.4.0", Depot: "releases"}},
			attendu: "pas connectée à ce core : compte rendu effacé"},
		{r: miseajourmanager.Relance{Ordre: &miseajour.Ordre{Version: "2.2.0", Retrograder: true}}, retro: "yes",
			echec: true},
		{r: miseajourmanager.Relance{Motif: "à jour (2.4.0)"}, attendu: "rien à faire — à jour"},
		{err: fmt.Errorf("agent %q %w", "x", dbclients.ErrIntrouvable), echec: true},
	}
	for i, c := range cas {
		var vuRetro bool
		relancer = func(id string, retro bool) (miseajourmanager.Relance, error) { vuRetro = retro; return c.r, c.err }
		res, err := relancerMiseAJour(Appelant{}, Params{"computeur_id": "poste-1", "downgrade": c.retro})
		if (err != nil) != c.echec || !strings.Contains(res.Message, c.attendu) {
			t.Errorf("cas %d : %q %v", i, res.Message, err)
		}
		if vuRetro != (c.retro == "yes") {
			t.Errorf("cas %d : --downgrade mal transmis", i)
		}
	}
	if _, err := relancerMiseAJour(Appelant{}, Params{}); err == nil {
		t.Error("machine manquante acceptée")
	}
}

func TestDefinirDepot(t *testing.T) {
	avant := ecrireDepot
	t.Cleanup(func() { ecrireDepot = avant })
	var ecrit = "?"
	ecrireDepot = func(d, _ string) error { ecrit = d; return nil }

	if res, err := definirDepot(Appelant{}, Params{"depot": "site-paris"}); err != nil || ecrit != "site-paris" ||
		!strings.Contains(res.Message, "site-paris") {
		t.Errorf("%q %v %q", res.Message, err, ecrit)
	}
	if res, err := definirDepot(Appelant{}, Params{"depot": "none"}); err != nil || ecrit != "" ||
		!strings.Contains(res.Message, "releases") {
		t.Errorf("effacement : %q %v %q", res.Message, err, ecrit)
	}
	ecrit = "?"
	if _, err := definirDepot(Appelant{}, Params{"depot": "Site/Paris"}); err == nil || ecrit != "?" {
		t.Error("nom de dépôt invalide accepté")
	}
}
