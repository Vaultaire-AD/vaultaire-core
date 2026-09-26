package clusterstorage

import "testing"

// Le trafic d'un proxy de parc se compte en gigaoctets dès la première journée.
// Ces tests portent sur la lisibilité de la colonne, qui est tout ce qu'on lui
// demande — le nombre exact est en base.
func TestOctetsLisibles(t *testing.T) {
	cas := []struct {
		octets int64
		attend string
		motif  string
	}{
		{0, "0 o", "un proxy qui vient de démarrer"},
		{512, "512 o", "sous le kibioctet, l'unité brute reste la plus claire"},
		{1024, "1,0 Kio", "la première unité"},
		{1536, "1,5 Kio", "la décimale sert à distinguer 1,5 de 1,9"},
		{1048576, "1,0 Mio", ""},
		{3145728, "3,0 Mio", ""},
		{1073741824, "1,0 Gio", ""},
		// LE cas qui justifie le calcul en entiers : un flottant arrondirait
		// vers le haut et afficherait « 1,0 Gio » pour un seuil non atteint.
		{1073741823, "1023,9 Mio", "on n'annonce pas un gibioctet qu'on n'a pas"},
	}

	for _, c := range cas {
		if got := OctetsLisibles(c.octets); got != c.attend {
			t.Errorf("OctetsLisibles(%d) = %q, attendu %q — %s",
				c.octets, got, c.attend, c.motif)
		}
	}
}

// Les deux causes d'échec sont additionnées pour la vue d'ensemble, et séparées
// dans la fiche : elles ne se règlent pas de la même façon — « aucune cible
// joignable » regarde le cluster, « plafond atteint » regarde la configuration
// du relais.
func TestEcarteesAdditionneLesDeuxCauses(t *testing.T) {
	m := MetriquesRelais{Refusees: 7, Rejetees: 2}
	if m.Ecartees() != 9 {
		t.Errorf("Ecartees() = %d, attendu 9", m.Ecartees())
	}
	r := RelaisMesure{Refusees: 1, Rejetees: 4}
	if r.Ecartees() != 5 {
		t.Errorf("RelaisMesure.Ecartees() = %d, attendu 5", r.Ecartees())
	}
}

// Le trafic affiché est celui des DEUX sens : une connexion relayée en porte
// forcément dans les deux, et n'en montrer qu'un diviserait le chiffre par deux
// sans que rien ne le dise.
func TestLeTraficCompteLesDeuxSens(t *testing.T) {
	m := MetriquesRelais{OctetsMontants: 1024, OctetsDescendants: 1024}
	if m.Octets() != 2048 {
		t.Errorf("Octets() = %d, attendu 2048", m.Octets())
	}
	if m.TraficLisible() != "2,0 Kio" {
		t.Errorf("TraficLisible() = %q, attendu « 2,0 Kio »", m.TraficLisible())
	}
}
