package decouverte

import (
	"encoding/json"
	"strings"
	"testing"
)

// Le point 108 : les mesures sont ÉMISES. Ces tests portent sur ce qui part sur
// le fil, parce que c'est le contrat avec le core — qui, lui, est dans un autre
// module et ne partage aucun code avec celui-ci.

// LE test du point : ce que le fournisseur rend part en 04_05.
func TestLesMesuresPartentEnTrame(t *testing.T) {
	var envoyees []string
	Configure(func(trame string) { envoyees = append(envoyees, trame) }, "machine-42")
	t.Cleanup(func() { Configure(nil, ""); ConfigurerMetriques(nil) })

	ConfigurerMetriques(func() []Metrique {
		return []Metrique{{
			Type:   TypeMetriqueRelais,
			Valeur: 3,
			Extra:  map[string]any{"total": 128},
		}}
	})

	emettreMetriques("cle-de-session", InfosNoeud{Hostname: "proxy1", IP: "10.0.0.2"})

	if len(envoyees) != 1 {
		t.Fatalf("%d trame(s) émise(s), attendu 1", len(envoyees))
	}
	lignes := strings.Split(envoyees[0], "\n")
	if lignes[0] != "04_05" {
		t.Errorf("trame %q, attendu 04_05", lignes[0])
	}
	if lignes[2] != "cle-de-session" {
		t.Errorf("clé de session %q", lignes[2])
	}
	if lignes[4] != "machine-42" {
		t.Errorf("identifiant client %q", lignes[4])
	}
	if lignes[5] != "proxy1" || lignes[6] != "10.0.0.2" {
		t.Errorf("nœud %q / %q", lignes[5], lignes[6])
	}
	if lignes[7] != TypeMetriqueRelais {
		t.Errorf("type %q, attendu %q", lignes[7], TypeMetriqueRelais)
	}
	if lignes[8] != "3" {
		t.Errorf("valeur %q, attendu 3", lignes[8])
	}

	// L'accompagnement doit être du JSON : le core refuse la trame entière
	// sinon, et la mesure serait perdue sans que le nœud ne l'apprenne.
	var extra map[string]any
	if err := json.Unmarshal([]byte(lignes[9]), &extra); err != nil {
		t.Fatalf("accompagnement illisible (%v) : %q", err, lignes[9])
	}
	if extra["total"] != float64(128) {
		t.Errorf("accompagnement = %v", extra)
	}
}

// Sans fournisseur branché, RIEN ne part.
//
// C'est le cas de tous les services autres que le proxy : ils rejoignent le
// cluster et battent, sans compteur à remonter. Une trame vide par battement et
// par service remplirait `proxy_metrics` de lignes qui ne disent rien, et la
// purge travaillerait pour rien.
func TestSansFournisseurRienNEstEmis(t *testing.T) {
	var envoyees []string
	Configure(func(trame string) { envoyees = append(envoyees, trame) }, "id")
	t.Cleanup(func() { Configure(nil, ""); ConfigurerMetriques(nil) })

	ConfigurerMetriques(nil)
	emettreMetriques("cle", InfosNoeud{Hostname: "core1"})

	if len(envoyees) != 0 {
		t.Errorf("%d trame(s) émise(s) sans fournisseur : %v", len(envoyees), envoyees)
	}
}

// Un fournisseur qui ne rend rien ne fait rien émettre non plus : c'est l'état
// d'un proxy avant l'ouverture de ses relais, qui a lieu APRÈS le raccordement
// au cluster.
func TestUnFournisseurVideNEmetRien(t *testing.T) {
	var envoyees []string
	Configure(func(trame string) { envoyees = append(envoyees, trame) }, "id")
	t.Cleanup(func() { Configure(nil, ""); ConfigurerMetriques(nil) })

	ConfigurerMetriques(func() []Metrique { return nil })
	emettreMetriques("cle", InfosNoeud{Hostname: "proxy1"})

	if len(envoyees) != 0 {
		t.Errorf("%d trame(s) émise(s) pour un fournisseur vide", len(envoyees))
	}
}

// Une mesure sans type ne part pas : elle se rangerait en base sous une clé que
// personne ne sait relire.
func TestUneMesureSansTypeNePartPas(t *testing.T) {
	var envoyees []string
	Configure(func(trame string) { envoyees = append(envoyees, trame) }, "id")
	t.Cleanup(func() { Configure(nil, ""); ConfigurerMetriques(nil) })

	ConfigurerMetriques(func() []Metrique {
		return []Metrique{{Type: "  ", Valeur: 1}, {Type: "bon", Valeur: 2}}
	})
	emettreMetriques("cle", InfosNoeud{Hostname: "proxy1"})

	if len(envoyees) != 1 {
		t.Fatalf("%d trame(s) émise(s), attendu 1 — la mesure sans type est passée", len(envoyees))
	}
	if strings.Split(envoyees[0], "\n")[7] != "bon" {
		t.Errorf("ce n'est pas la bonne mesure qui est partie : %q", envoyees[0])
	}
}

// L'accompagnement est TOUJOURS du JSON valide, y compris quand il est vide ou
// inencodable : le core refuse la trame entière sur un JSON cassé, et perdre la
// mesure à cause d'un champ d'accompagnement serait la mauvaise moitié à
// sacrifier.
func TestLAccompagnementEstToujoursDuJSON(t *testing.T) {
	cas := map[string]map[string]any{
		"nil":         nil,
		"vide":        {},
		"inencodable": {"canal": make(chan int)},
	}
	for nom, extra := range cas {
		rendu := extraJSON(extra)
		var quelconque any
		if err := json.Unmarshal([]byte(rendu), &quelconque); err != nil {
			t.Errorf("%s : accompagnement %q illisible (%v)", nom, rendu, err)
		}
	}
}

// La trame compte toujours dix lignes : le core lit la valeur en huitième
// position et recolle tout ce qui suit. Un champ ajouté au milieu décalerait
// tout, sans erreur visible — la valeur d'un nœud deviendrait son type.
func TestLaTrameGardeSesDixLignes(t *testing.T) {
	trame := ConstruireMetrique("cle", "id", InfosNoeud{Hostname: "h", IP: "1.2.3.4"},
		Metrique{Type: TypeMetriqueRelais, Valeur: 1, Extra: map[string]any{"a": 1}})
	if n := len(strings.Split(trame, "\n")); n != 10 {
		t.Errorf("%d ligne(s) dans la trame, attendu 10 :\n%s", n, trame)
	}
}
