package gpo

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestSanitizeDetailResteValideEnUTF8 : une coupure au milieu d'un caractère
// produit une chaîne que MariaDB en utf8mb4 REFUSE. L'INSERT échoue, le rapport
// entier est perdu — pour un message de diagnostic tronqué.
//
// Les messages d'erreur système sont précisément l'endroit où les accents
// abondent, donc l'endroit où ce défaut se déclenche.
func TestSanitizeDetailResteValideEnUTF8(t *testing.T) {
	// Le préfixe ASCII décale la limite de 240 OCTETS à l'intérieur du texte
	// multi-octets qui suit. Sans lui, le test ne prouverait rien : « é » fait
	// deux octets, 240 est pair, et la coupure tomberait toujours pile sur une
	// frontière — un test vert qui ne mesure rien.
	for prefixe := 0; prefixe < 6; prefixe++ {
		entree := strings.Repeat("a", prefixe) + strings.Repeat("é", 200)
		out := sanitizeDetail(entree)
		if !utf8.ValidString(out) {
			t.Errorf("sortie invalide en UTF-8 avec %d caractère(s) de préfixe", prefixe)
		}
	}

	// Même chose avec un caractère de trois octets, pour couvrir les autres
	// restes possibles de la division.
	for prefixe := 0; prefixe < 6; prefixe++ {
		entree := strings.Repeat("a", prefixe) + strings.Repeat("字", 200)
		if out := sanitizeDetail(entree); !utf8.ValidString(out) {
			t.Errorf("sortie invalide en UTF-8 (3 octets) avec %d de préfixe", prefixe)
		}
	}
}

// TestSanitizeDetailAplatit : sauts de ligne et séparateurs ne doivent pas
// survivre. Un « \n » dans le détail créerait une ligne de trame supplémentaire,
// que le serveur lirait comme un écart de plus.
func TestSanitizeDetailAplatit(t *testing.T) {
	out := sanitizeDetail("  erreur\nsur\rdeux | lignes  ")
	if strings.ContainsAny(out, "\n\r|") {
		t.Errorf("caractère structurant conservé : %q", out)
	}
	if out != "erreur sur deux / lignes" {
		t.Errorf("sortie %q inattendue", out)
	}
}

// TestSanitizePathNeMentPasSurLeChemin : « | » est légal dans un nom de fichier
// sous Linux.
//
// Le remplacer par « / » — ce que fait sanitizeDetail, à juste titre pour un
// message — transformerait /etc/a|b en /etc/a/b : un AUTRE chemin, plausible et
// faux, que l'administrateur irait inspecter en vain.
func TestSanitizePathNeMentPasSurLeChemin(t *testing.T) {
	out := sanitizePath("/etc/vaultaire/a|b.conf")
	if strings.Contains(out, "|") {
		t.Errorf("séparateur conservé, la trame serait ambiguë : %q", out)
	}
	if strings.Contains(out, "a/b") {
		t.Errorf("le chemin a été transformé en un autre chemin : %q", out)
	}
	if out != "/etc/vaultaire/a%7Cb.conf" {
		t.Errorf("sortie %q inattendue", out)
	}
}
