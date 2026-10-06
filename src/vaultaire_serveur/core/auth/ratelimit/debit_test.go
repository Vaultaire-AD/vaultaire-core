package ratelimit

import (
	"testing"
	"time"
)

// Le débit par source de l'API (TO-DO 102).

// TestUneRafaleLegitimePasse : un intégrateur qui envoie sa rafale d'un coup
// n'est pas freiné tant qu'elle tient dans le seau.
func TestUneRafaleLegitimePasse(t *testing.T) {
	avancer(t)
	d := NouveauDebit("test", 50, 10)
	for i := 0; i < 50; i++ {
		if ok, _ := d.Prendre("10.0.0.1"); !ok {
			t.Fatalf("requête %d de la rafale refusée : le seau en tient 50", i+1)
		}
	}
	ok, reste := d.Prendre("10.0.0.1")
	if ok {
		t.Fatal("la 51ᵉ requête immédiate passe : le seau ne borne rien")
	}
	if reste <= 0 || reste > 100*time.Millisecond {
		t.Errorf("délai annoncé %s, attendu dans ]0, 100 ms] à 10 jetons par seconde", reste)
	}
}

// TestUnFlotSoutenuEstRameneAuDebit : au-delà de la rafale, une source ne
// passe plus qu'au rythme du remplissage, quelle que soit la durée du flot.
func TestUnFlotSoutenuEstRameneAuDebit(t *testing.T) {
	horloge := avancer(t)
	d := NouveauDebit("test", 5, 2)
	passees := 0
	// Dix secondes à cent requêtes par seconde.
	for i := 0; i < 1000; i++ {
		if ok, _ := d.Prendre("10.0.0.2"); ok {
			passees++
		}
		horloge(10 * time.Millisecond)
	}
	// 5 de rafale + 2 par seconde pendant 10 s, à l'arrondi près.
	if passees < 23 || passees > 26 {
		t.Errorf("%d requêtes passées en 10 s, attendu ~25 (5 + 2 × 10)", passees)
	}
}

// TestLesSourcesSontIndependantes : une source qui sature ne freine pas les
// autres — sinon un seul balayage arrêterait tous les intégrateurs.
func TestLesSourcesSontIndependantes(t *testing.T) {
	avancer(t)
	d := NouveauDebit("test", 2, 1)
	d.Prendre("10.0.0.3")
	d.Prendre("10.0.0.3")
	if ok, _ := d.Prendre("10.0.0.3"); ok {
		t.Fatal("la source saturée passe encore")
	}
	if ok, _ := d.Prendre("10.0.0.4"); !ok {
		t.Fatal("une autre source est freinée par la première")
	}
}

// TestLeSeauSeRemplit : après une pause, la source retrouve sa rafale entière
// — et pas davantage, quelle que soit la durée de la pause.
func TestLeSeauSeRemplit(t *testing.T) {
	horloge := avancer(t)
	d := NouveauDebit("test", 3, 1)
	for i := 0; i < 3; i++ {
		d.Prendre("10.0.0.5")
	}
	horloge(time.Hour)
	passees := 0
	for i := 0; i < 10; i++ {
		if ok, _ := d.Prendre("10.0.0.5"); ok {
			passees++
		}
	}
	if passees != 3 {
		t.Errorf("%d requêtes passées après une heure de pause, attendu 3 (la rafale, plafonnée)", passees)
	}
}

// TestLesSeauxPleinsSontOublies : la table ne grossit pas indéfiniment.
func TestLesSeauxPleinsSontOublies(t *testing.T) {
	horloge := avancer(t)
	d := NouveauDebit("test", 10, 10)
	for i := 0; i < 100; i++ {
		d.Prendre("10.1.0." + string(rune('0'+i%10)) + string(rune('0'+i/10)))
	}
	if d.Taille() != 100 {
		t.Fatalf("%d sources suivies, attendu 100", d.Taille())
	}
	horloge(2 * time.Minute)
	d.Prendre("10.2.0.1")
	if d.Taille() != 1 {
		t.Errorf("%d sources encore suivies après la purge, attendu 1", d.Taille())
	}
}

// TestSourceVideNonFreinee : une requête sans source identifiable ne partage
// pas un seau avec toutes les autres.
func TestSourceVideNonFreinee(t *testing.T) {
	avancer(t)
	d := NouveauDebit("test", 1, 1)
	for i := 0; i < 5; i++ {
		if ok, _ := d.Prendre(""); !ok {
			t.Fatal("source vide freinée")
		}
	}
}
