package getlocalinformation

import (
	"strings"
	"testing"
)

// TO-DO 214 : la sortie brute de `nproc` (« 4\n ») ajoutait une ligne à
// l'inventaire, et le core lisait les sessions à la place de la version.
func TestLInventaireGardeQuatreLignes(t *testing.T) {
	materiel := ComposerMateriel("web01\n", "Rocky Linux 10.0\n", "7.5Gi/1.2Gi", "4\n")
	lignes := strings.Split(materiel, "\n")
	if len(lignes) != 4 {
		t.Fatalf("%d lignes, 4 attendues : %q", len(lignes), materiel)
	}
	if lignes[3] != "4" || lignes[0] != "web01" {
		t.Errorf("valeurs mal rognées : %q", lignes)
	}

	// La trame entière, telle que la compose userauth : matériel, sessions,
	// puis les deux versions. La version doit être à l'indice 5.
	trame := materiel + "\n" + "alice@acme.lan,root" + "\n" + "2.3.0+gabc (2026-10-25)" + "\n" + "2.1.0"
	champs := strings.Split(trame, "\n")
	if len(champs) != 7 || champs[5] != "2.3.0+gabc (2026-10-25)" {
		t.Fatalf("version à la mauvaise place : %q", champs)
	}
}

func TestUneLigne(t *testing.T) {
	for entree, attendu := range map[string]string{
		"4\n":           "4",
		"  a  ":         "a",
		"a\r\nb":        "a b",
		"a\n\nb\n":      "a b",
		"":              "",
		"Rocky Linux 9": "Rocky Linux 9",
	} {
		if obtenu := UneLigne(entree); obtenu != attendu {
			t.Errorf("UneLigne(%q) = %q, attendu %q", entree, obtenu, attendu)
		}
	}
}
