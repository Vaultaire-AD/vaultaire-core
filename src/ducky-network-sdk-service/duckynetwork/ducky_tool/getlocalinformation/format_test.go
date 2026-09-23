package getlocalinformation

import "testing"

// La colonne RAM du core reçoit les postes UNIX et les postes Windows. Ce test
// garde la seule chose qui compte : que les deux s'y lisent pareil.

func TestLeFormatSuitCeluiDeFree(t *testing.T) {
	cas := []struct {
		octets  uint64
		attendu string
	}{
		{0, "0B"},
		{512, "512B"},
		{1024, "1Ki"},
		{719323136, "686Mi"},    // ce que `free -h` écrit pour cette valeur
		{8321499136, "7.8Gi"},   // 7,75 arrondi à une décimale
		{8589934592, "8Gi"},     // pas « 8,0Gi » : free écrit « 8,0Gi » ? non, « 8Gi »
		{17179869184, "16Gi"},   //
		{137438953472, "128Gi"}, // au-delà de 100, plus de décimale
		{1099511627776, "1Ti"},  //
	}
	for _, c := range cas {
		if obtenu := FormatOctets(c.octets); obtenu != c.attendu {
			t.Errorf("FormatOctets(%d) = %q, attendu %q", c.octets, obtenu, c.attendu)
		}
	}
}

// Le POINT décimal, comme `free -h` en locale C — celle d'un service systemd,
// donc celle dans laquelle le parc Linux envoie ses inventaires. Une virgule
// ici mélangerait « 7.8Gi » et « 7,8Gi » dans la même colonne du core.
func TestLaDecimaleEstUnPoint(t *testing.T) {
	s := FormatOctets(8321499136)
	for _, c := range s {
		if c == ',' {
			t.Fatalf("%q porte une virgule décimale", s)
		}
	}
}

// Aucune valeur ne doit produire une chaîne vide : la colonne d'inventaire
// serait alors indistinguable d'une collecte en échec.
func TestAucuneValeurNeRendUneChaineVide(t *testing.T) {
	for _, v := range []uint64{0, 1, 1023, 1024, 1<<40 - 1, 1 << 50, ^uint64(0)} {
		if FormatOctets(v) == "" {
			t.Errorf("FormatOctets(%d) rend une chaîne vide", v)
		}
	}
}
