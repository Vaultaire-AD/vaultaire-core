package commandcreate

import (
	"strings"
	"testing"
)

// Le découpage des options de « create -c » / « create -export ».
//
// Éprouvé ici parce que c'est du texte pur — aucune base, aucun réseau — et
// parce que chacun de ses défauts était SILENCIEUX : une option avalée sans
// valeur, un « -join » cherché au mauvais endroit. Rien ne tombait, rien ne se
// disait, et l'archive n'existait simplement pas.

func TestUneOptionSansValeurEstRefusee(t *testing.T) {
	for _, args := range [][]string{
		{"non", "--export"},
		{"non", "--os"},
		{"non", "--export", "/tmp/x.zip", "--os"},
	} {
		_, _, err := extraireOptionsClient(args)
		if err == "" {
			t.Errorf("%v : accepte en silence", args)
		} else if !strings.Contains(err, "valeur") {
			t.Errorf("%v : le refus ne dit pas ce qui manque (%q)", args, err)
		}
	}
}

func TestLesOptionsSortentDesPositionnels(t *testing.T) {
	options, positionnels, err := extraireOptionsClient(
		[]string{"non", "--os", "windows", "-join", "hote", "root", "--export", "/tmp/x.zip"})
	if err != "" {
		t.Fatalf("refus inattendu : %s", err)
	}
	if options["systeme"] != "windows" || options["export"] != "/tmp/x.zip" {
		t.Errorf("options mal lues : %v", options)
	}

	// Les positionnels doivent rester dans l'ORDRE et ne porter que
	// l'essentiel : c'est sur eux que « -join » est cherché, et une option
	// laissée dedans décalerait l'hôte et l'utilisateur d'un cran.
	attendu := []string{"non", "-join", "hote", "root"}
	if len(positionnels) != len(attendu) {
		t.Fatalf("positionnels = %v, attendu %v", positionnels, attendu)
	}
	for i := range attendu {
		if positionnels[i] != attendu[i] {
			t.Fatalf("positionnels = %v, attendu %v", positionnels, attendu)
		}
	}
}

// « -join » doit être trouvé quelle que soit la place des options.
//
// La version d'origine le cherchait dans la liste BRUTE, à l'indice 2 : mettre
// « --os » avant lui le rendait invisible, et l'intégration à distance était
// abandonnée sans un mot.
func TestJoinEstTrouveQuelleQueSoitLaPlaceDesOptions(t *testing.T) {
	for _, args := range [][]string{
		{"non", "-join", "hote", "root"},
		{"non", "--os", "linux", "-join", "hote", "root"},
		{"non", "-join", "hote", "root", "--os", "linux"},
	} {
		_, positionnels, err := extraireOptionsClient(args)
		if err != "" {
			t.Fatalf("%v : refus inattendu %s", args, err)
		}
		if len(positionnels) < 2 || positionnels[1] != "-join" {
			t.Errorf("%v : « -join » introuvable dans %v", args, positionnels)
		}
	}
}

// Le cas qui faisait PANIQUER le serveur.
//
// « create -c non -join hote » fait exactement quatre éléments : l'ancien code
// contrôlait « len >= 4 » puis lisait l'indice 4. Le contrôle porte désormais
// sur les positionnels, dont il faut QUATRE — le booléen, « -join », l'hôte et
// l'utilisateur.
func TestJoinIncompletNeLaissePasLireHorsBornes(t *testing.T) {
	_, positionnels, err := extraireOptionsClient([]string{"non", "-join", "hote"})
	if err != "" {
		t.Fatalf("refus inattendu : %s", err)
	}
	if len(positionnels) >= 4 {
		t.Fatalf("positionnels = %v : le contrôle de borne ne protégerait rien", positionnels)
	}
}
