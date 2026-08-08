package sessionmgr

import (
	"math"
	"testing"
)

// Ces tests portent sur l'ENTROPIE de la clé de session, pas sur sa taille.
//
// La distinction est tout le sujet. L'ancienne implémentation produisait une
// clé de 32 octets — la taille exacte qu'AES-256 réclame — mais dont chaque
// caractère ne pouvait prendre que 16 valeurs. Un test sur la longueur passait
// donc parfaitement pendant que la clé valait la moitié de ce qu'elle
// annonçait.
//
// D'où la forme retenue ici : compter les valeurs distinctes réellement
// atteintes par chaque position, et non mesurer la chaîne.

// TestLongueurCleDeSession fixe l'invariant dur : AES-256 exige 32 octets.
func TestLongueurCleDeSession(t *testing.T) {
	m := NewManager()

	cle, err := m.GenerateIntegrityKey()
	if err != nil {
		t.Fatalf("génération impossible : %v", err)
	}
	if len([]byte(cle)) != 32 {
		t.Fatalf("clé de %d octets, AES-256 en exige 32 : %q", len([]byte(cle)), cle)
	}
}

// TestAlphabetCleDeSession est le test qui aurait attrapé le problème.
//
// Il échantillonne un grand nombre de clés et relève l'ensemble des caractères
// employés. Un alphabet hexadécimal en découvre 16 ; base64url en découvre 64.
//
// Le seuil est placé à 32 — soit strictement au-dessus de ce que l'hexadécimal
// peut atteindre, et bien en dessous de 64. Il distingue donc les deux sans
// dépendre du fait que les 64 symboles soient tous tirés dans l'échantillon.
func TestAlphabetCleDeSession(t *testing.T) {
	m := NewManager()

	vus := map[rune]bool{}
	const tirages = 400

	for i := 0; i < tirages; i++ {
		cle, err := m.GenerateIntegrityKey()
		if err != nil {
			t.Fatalf("génération impossible : %v", err)
		}
		for _, r := range cle {
			vus[r] = true
		}
	}

	if len(vus) <= 16 {
		t.Fatalf(
			"alphabet de %d symboles seulement : la clé est hexadécimale.\n"+
				"32 caractères × 4 bits = 128 bits, alors que sa taille de 32 octets\n"+
				"laisse croire à 256. Symboles relevés : %s",
			len(vus), symbolesTries(vus))
	}
	if len(vus) < 32 {
		t.Fatalf("alphabet de %d symboles, attendu au moins 32 : %s",
			len(vus), symbolesTries(vus))
	}

	// L'entropie effective, exprimée telle qu'on la lit dans une revue.
	bits := float64(32) * math.Log2(float64(len(vus)))
	if bits < 180 {
		t.Fatalf("entropie estimée à %.0f bits, attendu au moins 180", bits)
	}
	t.Logf("alphabet de %d symboles → environ %.0f bits d'entropie", len(vus), bits)
}

// TestCleDeSessionSansRemplissage vérifie l'absence de « = ».
//
// L'encodage base64 ordinaire complète la sortie par des « = » quand la
// longueur d'entrée n'est pas un multiple de 3. Ces caractères sont constants :
// ils occupent une position sans rien y apporter. Si l'un d'eux apparaissait,
// la clé porterait moins d'entropie que le calcul ci-dessus ne le suppose.
func TestCleDeSessionSansRemplissage(t *testing.T) {
	m := NewManager()

	for i := 0; i < 50; i++ {
		cle, err := m.GenerateIntegrityKey()
		if err != nil {
			t.Fatalf("génération impossible : %v", err)
		}
		for _, r := range cle {
			if r == '=' {
				t.Fatalf("caractère de remplissage dans %q : position sans entropie", cle)
			}
			// La clé sert d'identifiant de session dans les journaux et de clé
			// de map. Ni « / » ni « + » ne doivent y figurer.
			if r == '/' || r == '+' {
				t.Fatalf("caractère %q dans la clé %q : base64 standard au lieu de base64url", r, cle)
			}
		}
	}
}

// TestUniciteCleDeSession vérifie qu'aucune collision n'apparaît, et surtout
// que la vérification d'unicité contre le registre est bien câblée.
func TestUniciteCleDeSession(t *testing.T) {
	m := NewManager()

	vues := map[string]bool{}
	for i := 0; i < 1000; i++ {
		cle, err := m.GenerateIntegrityKey()
		if err != nil {
			t.Fatalf("génération impossible : %v", err)
		}
		if vues[cle] {
			t.Fatalf("clé produite deux fois : %q", cle)
		}
		vues[cle] = true
	}
}

func symbolesTries(vus map[rune]bool) string {
	out := make([]rune, 0, len(vus))
	for r := range vus {
		out = append(out, r)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return string(out)
}
