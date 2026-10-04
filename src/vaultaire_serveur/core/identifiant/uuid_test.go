package identifiant

import "testing"

func TestNouvelUUIDRendLaFormeCanonique(t *testing.T) {
	vus := map[string]bool{}
	for i := 0; i < 2000; i++ {
		u, err := NouvelUUID()
		if err != nil {
			t.Fatal(err)
		}
		if !EstUnUUID(u) {
			t.Fatalf("%q n'est pas un UUID canonique : un client strict rejetterait l'entrée", u)
		}
		if u[14] != '4' {
			t.Fatalf("%q : version %c, attendu 4 (aléatoire)", u, u[14])
		}
		if c := u[19]; c != '8' && c != '9' && c != 'a' && c != 'b' {
			t.Fatalf("%q : variante %c, attendu 8, 9, a ou b (RFC 4122)", u, c)
		}
		if vus[u] {
			t.Fatalf("%q tiré deux fois : deux entrées porteraient le même identifiant", u)
		}
		vus[u] = true
	}
}

func TestEstUnUUIDRefuseCeQuiNEnEstPas(t *testing.T) {
	for _, s := range []string{
		"",
		"alice",                                  // ce que l'attribut portait avant le point 129
		"vaultaire-alice",                        // idem, pour les variantes propriétaires
		"597AE2F6-16A6-1027-98F4-D28B5365DC14",   // majuscules : forme non canonique
		"597ae2f616a6102798f4d28b5365dc14",       // sans tirets
		"597ae2f6-16a6-1027-98f4-d28b5365dc1",    // trop court
		"597ae2f6-16a6-1027-98f4-d28b5365dc14 ",  // espace
		"597ae2f6-16a6-1027-98f4-d28b5365dg14",   // pas de l'hexadécimal
		"{597ae2f6-16a6-1027-98f4-d28b5365dc14}", // forme Windows
	} {
		if EstUnUUID(s) {
			t.Errorf("EstUnUUID(%q) = vrai", s)
		}
	}
	if !EstUnUUID("597ae2f6-16a6-1027-98f4-d28b5365dc14") {
		t.Error("l'exemple de la RFC 4530 est refusé")
	}
}
