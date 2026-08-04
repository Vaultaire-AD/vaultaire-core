package qrcode

import "testing"

// Vecteur de référence : « HELLO WORLD » en mode octet, version 1, niveau M.
//
// Ces codewords ont été confrontés à deux implémentations tierces indépendantes
// (segno et python-qrcode). La matrice produite est identique, module pour
// module, à celle de python-qrcode.
func TestCodewordsKnownVector(t *testing.T) {
	want := []byte{
		0x40, 0xb4, 0x84, 0x54, 0xc4, 0xc4, 0xf2, 0x05, 0x74, 0xf5, 0x24, 0xc4, 0x40,
		0xec, 0x11, 0xec, // remplissage alterné imposé par la norme
		0x0c, 0x4b, 0xcf, 0x9a, 0x89, 0x4f, 0x65, 0x09, 0x97, 0xcc, // correction d'erreur
	}
	got := buildCodewords([]byte("HELLO WORLD"), 1)
	if len(got) != len(want) {
		t.Fatalf("longueur %d, attendu %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("codeword %d = %#02x, attendu %#02x", i, got[i], want[i])
		}
	}
}

// TestFormatInfo vérifie les quinze bits d'information de format contre la table
// normalisée du niveau M. Une erreur ici rend le symbole illisible sans qu'aucun
// autre contrôle ne s'en aperçoive : le lecteur ne saurait plus quel masque
// retirer.
func TestFormatInfo(t *testing.T) {
	want := []string{
		"101010000010010", "101000100100101", "101111001111100", "101101101001011",
		"100010111111001", "100000011001110", "100111110010111", "100101010100000",
	}
	for pattern, expected := range want {
		m := Matrix{Size: 21, Modules: make([]bool, 21*21)}
		writeFormatInfo(&m, pattern)
		got := ""
		for i := 14; i >= 0; i-- {
			var x, y int
			switch {
			case i < 6:
				x, y = 8, i
			case i == 6:
				x, y = 8, 7
			case i == 7:
				x, y = 8, 8
			case i == 8:
				x, y = 7, 8
			default:
				x, y = 14-i, 8
			}
			if m.at(x, y) {
				got += "1"
			} else {
				got += "0"
			}
		}
		if got != expected {
			t.Errorf("masque %d : %s, attendu %s", pattern, got, expected)
		}
	}
}

// TestRoundTrip démasque la matrice produite et vérifie qu'on y relit exactement
// les codewords encodés. C'est ce que fait un lecteur : si ce test passe, le
// symbole est cohérent avec lui-même.
func TestRoundTrip(t *testing.T) {
	for _, content := range []string{
		"HELLO WORLD",
		"otpauth://totp/Vaultaire:admin@vaultaire.fr?secret=JBSWY3DPEHPK3PXP&issuer=Vaultaire",
		"a", "abcdefghijklmn",
	} {
		m, err := Encode(content)
		if err != nil {
			t.Fatalf("%q : %v", content, err)
		}
		version := (m.Size - 17) / 4
		want := buildCodewords([]byte(content), version)

		pattern := readFormatPattern(m)
		c := newCanvas(version)
		got := readCodewords(m, c, pattern, len(want))
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q : codeword %d relu %#02x, encodé %#02x", content, i, got[i], want[i])
			}
		}
	}
}

// TestTooLong refuse plutôt que de tronquer : un QR code tronqué se lit très
// bien et livre un mauvais secret.
func TestTooLong(t *testing.T) {
	if _, err := Encode(string(make([]byte, 300))); err == nil {
		t.Fatal("un contenu de 300 octets aurait dû être refusé")
	}
}

// readFormatPattern relit le masque déclaré par le symbole.
func readFormatPattern(m *Matrix) int {
	for pattern := 0; pattern < 8; pattern++ {
		probe := Matrix{Size: m.Size, Modules: make([]bool, len(m.Modules))}
		writeFormatInfo(&probe, pattern)
		same := true
		for i := 0; i < 6 && same; i++ {
			same = probe.at(8, i) == m.at(8, i)
		}
		if same {
			return pattern
		}
	}
	return -1
}

// readCodewords parcourt la matrice dans l'ordre de placement et retire le masque.
func readCodewords(m *Matrix, c *canvas, pattern, count int) []byte {
	var bits []bool
	n := m.Size
	upward := true
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for i := 0; i < n; i++ {
			y := i
			if upward {
				y = n - 1 - i
			}
			for _, x := range []int{right, right - 1} {
				if c.isReserved(x, y) {
					continue
				}
				v := m.at(x, y)
				if maskCondition(pattern, x, y) {
					v = !v
				}
				bits = append(bits, v)
			}
		}
		upward = !upward
	}
	out := make([]byte, count)
	for i := 0; i < count*8 && i < len(bits); i++ {
		if bits[i] {
			out[i/8] |= 0x80 >> uint(i%8)
		}
	}
	return out
}
