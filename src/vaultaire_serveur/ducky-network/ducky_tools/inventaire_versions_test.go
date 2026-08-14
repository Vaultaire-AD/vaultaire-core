package ducky_tools

import (
	"strings"
	"testing"
)

// La lecture des versions dans l'inventaire 02_12.
//
// # Ce que ces tests gardent
//
// Que l'ajout des versions n'ait CASSÉ AUCUN AGENT existant. Les deux lignes
// sont en queue de trame et facultatives : un agent d'une version antérieure en
// envoie cinq, et doit continuer d'être enregistré normalement.
//
// C'est le risque réel de ce lot. Le reste — afficher une chaîne — ne casse
// rien ; un inventaire refusé coupe la remontée d'état de tout le parc.

func TestUnAgentAncienResteLu(t *testing.T) {
	// Cinq lignes : ce qu'envoyait un agent avant ce lot.
	ancien := []string{"poste-01", "Ubuntu 22.04", "16 Go", "8", "alice,bob"}

	programme, sdk := VersionsDeLInventaire(ancien)

	if programme != "" || sdk != "" {
		t.Errorf("versions = %q / %q, attendu vides : un agent ancien n'en "+
			"déclare aucune", programme, sdk)
	}
}

func TestUnAgentAJourEstLu(t *testing.T) {
	recent := []string{
		"poste-01", "Ubuntu 22.04", "16 Go", "8", "alice,bob",
		"2.1.0+g1939a3b (2026-08-14)",
		"2.1.0+g1939a3b (2026-08-14)",
	}

	programme, sdk := VersionsDeLInventaire(recent)

	if programme != "2.1.0+g1939a3b (2026-08-14)" {
		t.Errorf("version de l'agent = %q", programme)
	}
	if sdk != "2.1.0+g1939a3b (2026-08-14)" {
		t.Errorf("version du SDK = %q", sdk)
	}
}

// TestUneSeuleLigneDeVersionNeDecalePas.
//
// Cas d'une trame tronquée, ou d'un agent qui aurait posé sa version sans que
// le socle ait la sienne. La version du programme doit être lue, celle du SDK
// rester vide — et surtout pas prendre la valeur de l'autre.
func TestUneSeuleLigneDeVersionNeDecalePas(t *testing.T) {
	partiel := []string{"poste-01", "Ubuntu", "16 Go", "8", "", "2.1.0"}

	programme, sdk := VersionsDeLInventaire(partiel)

	if programme != "2.1.0" {
		t.Errorf("version de l'agent = %q, attendu 2.1.0", programme)
	}
	if sdk != "" {
		t.Errorf("version du SDK = %q, attendu vide : elle n'a pas été envoyée", sdk)
	}
}

// TestUneVersionNeCassePasUnTableau.
//
// La valeur vient du réseau. Elle finit dans une colonne, puis dans les
// tableaux de `vlt` et dans une page web. Un retour chariot y ferait sauter une
// ligne au milieu d'un tableau aligné, et un caractère de contrôle peut faire
// bien pire dans un terminal.
func TestUneVersionNeCassePasUnTableau(t *testing.T) {
	sales := []string{
		"poste-01", "Ubuntu", "16 Go", "8", "",
		"2.1.0\r\n<injection>",
		"2.1.0\x1b[31m",
	}

	programme, sdk := VersionsDeLInventaire(sales)

	for nom, v := range map[string]string{"agent": programme, "sdk": sdk} {
		if strings.ContainsAny(v, "\n\r\x1b") {
			t.Errorf("version %s = %q : caractère de contrôle non écarté", nom, v)
		}
	}
}

// TestUneVersionTropLongueEstTronqueeIci.
//
// La colonne fait 64 caractères. Tronquer NOUS-MÊMES plutôt que laisser MySQL
// le faire : en mode non strict, sa troncature est silencieuse, et on lirait
// une version coupée sans jamais savoir qu'elle l'a été.
func TestUneVersionTropLongueEstTronqueeIci(t *testing.T) {
	longue := strings.Repeat("x", 200)
	lignes := []string{"h", "os", "ram", "proc", "", longue, longue}

	programme, sdk := VersionsDeLInventaire(lignes)

	if len(programme) > LongueurMaxVersion {
		t.Errorf("version de l'agent : %d caractères, maximum %d",
			len(programme), LongueurMaxVersion)
	}
	if len(sdk) > LongueurMaxVersion {
		t.Errorf("version du SDK : %d caractères, maximum %d",
			len(sdk), LongueurMaxVersion)
	}
}

// TestUnInventaireVideNePaniquePas : robustesse de l'indexation.
func TestUnInventaireVideNePaniquePas(t *testing.T) {
	for _, lignes := range [][]string{nil, {}, {"h"}, {"h", "os", "ram", "proc"}} {
		programme, sdk := VersionsDeLInventaire(lignes)
		if programme != "" || sdk != "" {
			t.Errorf("%v → %q / %q, attendu vides", lignes, programme, sdk)
		}
	}
}
