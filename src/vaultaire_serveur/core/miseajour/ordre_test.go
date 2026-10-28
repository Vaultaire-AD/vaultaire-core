package miseajour

import (
	"strings"
	"testing"

	"vaultaire/core/parcversion"
)

func attendue(v string) parcversion.Attendue {
	x, _ := parcversion.Lire(v)
	return parcversion.Attendue{Definie: true, Version: x, Source: parcversion.SourceParc}
}

func TestDecider(t *testing.T) {
	cas := []struct {
		nom   string
		s     Situation
		ordre bool
		motif string
	}{
		{nom: "sans cible", s: Situation{Declaree: "2.3.0"}, motif: "aucune version attendue"},
		{nom: "à jour", s: Situation{Declaree: "2.4.0+gabc", Attendue: attendue("2.4.0")}, motif: "à jour"},
		{nom: "en avance", s: Situation{Declaree: "2.5.0", Attendue: attendue("2.4.0")}, motif: "jamais rétrogradée"},
		{nom: "en retard", s: Situation{Declaree: "2.3.0", Attendue: attendue("2.4.0")}, ordre: true},
		{nom: "inconnue", s: Situation{Declaree: "", Attendue: attendue("2.4.0")}, ordre: true},
		{nom: "échec de cette version", s: Situation{Declaree: "2.3.0", Attendue: attendue("2.4.0"),
			CompteRendu: CompteRendu{Version: "2.4.0", Resultat: ResultatEchec, Motif: "socket PAM muet"}},
			motif: "vlt agent update"},
		{nom: "non pris en charge de cette version", s: Situation{Declaree: "2.3.0", Attendue: attendue("2.4.0"),
			CompteRendu: CompteRendu{Version: "2.4.0", Resultat: ResultatNonPrisEnCharge}}, motif: "non_pris_en_charge"},
		// Un échec d'une AUTRE version ne retient pas l'ordre : la cible a
		// changé, c'est un essai neuf.
		{nom: "échec d'une autre version", s: Situation{Declaree: "2.3.0", Attendue: attendue("2.4.1"),
			CompteRendu: CompteRendu{Version: "2.4.0", Resultat: ResultatEchec}}, ordre: true},
		{nom: "installé puis cible relevée", s: Situation{Declaree: "2.4.0", Attendue: attendue("2.4.1"),
			CompteRendu: CompteRendu{Version: "2.4.0", Resultat: ResultatInstalle}}, ordre: true},
	}
	for _, c := range cas {
		d := Decider(c.s)
		if (d.Ordre != nil) != c.ordre || !strings.Contains(d.Motif, c.motif) {
			t.Errorf("%s : %+v", c.nom, d)
		}
		if d.Ordre != nil && (d.Ordre.Depot != DepotParDefaut || d.Ordre.Retrograder) {
			t.Errorf("%s : ordre %+v", c.nom, *d.Ordre)
		}
	}
	d := Decider(Situation{Declaree: "2.3.0", Attendue: attendue("2.4.0"), Depot: "site"})
	if d.Ordre == nil || d.Ordre.Depot != "site" {
		t.Errorf("dépôt réglé : %+v", d)
	}
}

func TestComprendLaCategorie(t *testing.T) {
	for v, attendu := range map[string]bool{
		"2.3.0": true, "2.3.0 (build local)": true, "2.4.1+g12": true,
		"2.2.9": false, "": false, "dev": false,
	} {
		if ComprendLaCategorie(v) != attendu {
			t.Errorf("%q : %v", v, !attendu)
		}
	}
}

func TestLireCompteRendu(t *testing.T) {
	c, err := LireCompteRendu("2.4.0\nechec\nsocket PAM muet\n")
	if err != nil || c.Version != "2.4.0" || c.Resultat != ResultatEchec || c.Motif != "socket PAM muet" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, mauvais := range []string{"", "x\ninstalle", "2.4.0\nok", "2.4.0"} {
		if _, err := LireCompteRendu(mauvais); err == nil {
			t.Errorf("%q accepté", mauvais)
		}
	}
}

func TestNormaliserDepot(t *testing.T) {
	if d, err := NormaliserDepot(" releases "); err != nil || d != "releases" {
		t.Errorf("%q %v", d, err)
	}
	for _, m := range []string{"", "Releases", "a/b", "../x", "-x", strings.Repeat("a", 65)} {
		if _, err := NormaliserDepot(m); err == nil {
			t.Errorf("%q accepté", m)
		}
	}
}

func TestContenuDeLOrdre(t *testing.T) {
	if got := strings.Join(Ordre{Version: "2.4.0", Depot: "releases", Retrograder: true}.Contenu(), "|"); got != "2.4.0|releases|oui" {
		t.Errorf("%s", got)
	}
}

func TestDeciderPourRelance(t *testing.T) {
	echec := CompteRendu{Version: "2.4.0", Resultat: ResultatEchec}
	d, err := DeciderPourRelance(Situation{Declaree: "2.3.0", Attendue: attendue("2.4.0"), CompteRendu: echec}, false)
	if err != nil || d.Ordre == nil {
		t.Errorf("la relance passe outre l'échec : %+v %v", d, err)
	}
	d, _ = DeciderPourRelance(Situation{Declaree: "2.5.0", Attendue: attendue("2.4.0")}, false)
	if d.Ordre != nil || !strings.Contains(d.Motif, "--downgrade") {
		t.Errorf("en avance sans --downgrade : %+v", d)
	}
	d, _ = DeciderPourRelance(Situation{Declaree: "2.5.0", Attendue: attendue("2.4.0")}, true)
	if d.Ordre == nil || !d.Ordre.Retrograder || d.Ordre.Version != "2.4.0" {
		t.Errorf("rétrogradation explicite : %+v", d)
	}
	// --downgrade sur une machine en retard : un ordre ordinaire, sans le drapeau.
	d, _ = DeciderPourRelance(Situation{Declaree: "2.3.0", Attendue: attendue("2.4.0")}, true)
	if d.Ordre == nil || d.Ordre.Retrograder {
		t.Errorf("en retard avec --downgrade : %+v", d)
	}
	if _, err := DeciderPourRelance(Situation{Declaree: "2.3.0"}, false); err == nil {
		t.Error("sans cible : pas d'erreur")
	}
}

// Les résultats : les mêmes chaînes que l'agent Linux (vaultaire_client/
// miseajour) et l'agent Windows (gpo.ResultatNonPrisEnCharge).
func TestLesResultatsSontCeuxDesAgents(t *testing.T) {
	for got, attendu := range map[string]string{
		ResultatInstalle: "installe", ResultatEchec: "echec",
		ResultatRefuse: "refuse", ResultatNonPrisEnCharge: "non_pris_en_charge",
	} {
		if got != attendu {
			t.Errorf("%q, les agents écrivent %q", got, attendu)
		}
	}
}

// TO-DO 204 : la rétrogradation durable, portée par la dérogation seule.
func TestRetrogradationDurable(t *testing.T) {
	derog := func(v string) parcversion.Attendue {
		a := attendue(v)
		a.Source = parcversion.SourceMachine
		return a
	}
	groupe := attendue("2.2.0")
	groupe.Source, groupe.Groupe = parcversion.SourceGroupe, "pilote"

	// Dérogation + drapeau + machine en avance : ordre de rétrograder.
	d := Decider(Situation{Declaree: "2.4.0", Attendue: derog("2.2.0"), RetrogradationDemandee: true})
	if d.Ordre == nil || !d.Ordre.Retrograder || d.Ordre.Version != "2.2.0" {
		t.Fatalf("%+v", d)
	}
	// Le drapeau ne vaut que pour une cible venue de la dérogation.
	if d := Decider(Situation{Declaree: "2.4.0", Attendue: groupe, RetrogradationDemandee: true}); d.Ordre != nil {
		t.Errorf("une cible de groupe rétrograde : %+v", d)
	}
	// Sans drapeau, rien.
	if d := Decider(Situation{Declaree: "2.4.0", Attendue: derog("2.2.0")}); d.Ordre != nil {
		t.Errorf("%+v", d)
	}
	// Machine en retard : ordre ordinaire, sans drapeau de rétrogradation.
	if d := Decider(Situation{Declaree: "2.1.0", Attendue: derog("2.2.0"), RetrogradationDemandee: true}); d.Ordre == nil || d.Ordre.Retrograder {
		t.Errorf("%+v", d)
	}
	// Une rétrogradation ratée n'est pas retentée à chaque connexion.
	if d := Decider(Situation{Declaree: "2.4.0", Attendue: derog("2.2.0"), RetrogradationDemandee: true,
		CompteRendu: CompteRendu{Version: "2.2.0", Resultat: ResultatEchec}}); d.Ordre != nil {
		t.Errorf("échec retenté : %+v", d)
	}
	// « agent update » sans --downgrade la relance aussi, puisqu'elle est demandée.
	r, err := DeciderPourRelance(Situation{Declaree: "2.4.0", Attendue: derog("2.2.0"), RetrogradationDemandee: true}, false)
	if err != nil || r.Ordre == nil || !r.Ordre.Retrograder {
		t.Errorf("%+v %v", r, err)
	}
}
