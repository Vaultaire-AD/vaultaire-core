package sendmessage

import (
	"strings"
	"testing"

	keydecodeencode "vaultaire/ducky-network/key_decode_encode"
)

// TestTailleChiffree tient le calcul égal à ce que le chiffrement rend
// (TO-DO 138).
//
// TailleChiffree décide si un compte est refusé pour le poids de ses clés. Un
// calcul qui s'écarterait du vrai chiffrement d'un seul octet refuserait un
// compte qui passe, ou — pire — laisserait partir vers SendMessage une trame
// qu'il rejettera sans nommer personne. Si le format du chiffrement change, ce
// test échoue ici plutôt que sur un poste.
func TestTailleChiffree(t *testing.T) {
	cle := make([]byte, 32)
	for _, n := range []int{0, 1, 2, 3, 17, 255, 4096, 49123, 49124, 49125, 49126, 70000} {
		chiffre, err := keydecodeencode.EncryptAESGCMString(cle, strings.Repeat("x", n))
		if err != nil {
			t.Fatal(err)
		}
		if got := TailleChiffree(n); got != len(chiffre) {
			t.Errorf("TailleChiffree(%d) = %d, le chiffrement rend %d octets", n, got, len(chiffre))
		}
	}
}

// TestTientDansUneTrameSuitCadrerTrame : la question posée avant d'émettre et
// le refus à l'émission doivent tomber du même côté, à l'octet près.
func TestTientDansUneTrameSuitCadrerTrame(t *testing.T) {
	cle := make([]byte, 32)
	// Autour de la frontière : 65535 octets de base64 portent 49124 octets
	// de clair (49124 + 28 = 49152 = 3 × 16384, soit 65536 — juste au-dessus).
	for n := 49100; n <= 49140; n++ {
		message := strings.Repeat("x", n)
		chiffre, err := keydecodeencode.EncryptAESGCMString(cle, message)
		if err != nil {
			t.Fatal(err)
		}
		_, errCadre := CadrerTrame([]byte(chiffre))
		if tient := TientDansUneTrame(message); tient != (errCadre == nil) {
			t.Fatalf("message de %d octets : TientDansUneTrame = %v, CadrerTrame rend %v", n, tient, errCadre)
		}
	}
}
