package ldapbindunbind

import (
	"testing"
	"time"
)

// réinitialiser vide les compteurs entre deux tests.
func réinitialiser() {
	throttleMu.Lock()
	defer throttleMu.Unlock()
	parSource = map[string]*compteur{}
	parCompte = map[string]*compteur{}
	dernierPurge = time.Time{}
}

// TestSeuilPuisDélai : le seuil laisse passer, le dépassement freine.
//
// Un utilisateur qui se trompe une ou deux fois ne doit rien sentir ; un
// balayage doit ralentir.
func TestSeuilPuisDélai(t *testing.T) {
	réinitialiser()

	for i := 0; i < SeuilÉchecs; i++ {
		EnregistrerÉchec("10.0.0.1", "alice")
		if ok, _ := BindAutorisé("10.0.0.1", "alice"); !ok {
			t.Fatalf("bloqué dès le %dᵉ échec, alors que le seuil est %d", i+1, SeuilÉchecs)
		}
	}

	EnregistrerÉchec("10.0.0.1", "alice")
	ok, reste := BindAutorisé("10.0.0.1", "alice")
	if ok {
		t.Fatal("non bloqué après dépassement du seuil")
	}
	if reste <= 0 {
		t.Errorf("délai restant = %s, attendu positif", reste)
	}
}

// TestDeuxAxesIndépendants : l'adresse et le compte comptent séparément.
//
// Compter uniquement par adresse laisse passer un botnet ; uniquement par compte,
// un balayage de comptes depuis une seule machine.
func TestDeuxAxesIndépendants(t *testing.T) {
	réinitialiser()

	// Une seule adresse, des comptes tous différents : l'axe ADRESSE doit freiner.
	for i := 0; i <= SeuilÉchecs; i++ {
		EnregistrerÉchec("10.0.0.2", string(rune('a'+i)))
	}
	if ok, _ := BindAutorisé("10.0.0.2", "personne"); ok {
		t.Error("balayage de comptes depuis une même adresse non freiné")
	}

	réinitialiser()

	// Un seul compte, des adresses toutes différentes : l'axe COMPTE doit freiner.
	for i := 0; i <= SeuilÉchecs; i++ {
		EnregistrerÉchec("10.0.1."+string(rune('0'+i)), "bob")
	}
	if ok, _ := BindAutorisé("192.168.0.1", "bob"); ok {
		t.Error("balayage de mots de passe depuis plusieurs adresses non freiné")
	}
}

// TestSuccèsEfface : une authentification réussie remet les compteurs à zéro.
//
// Sans cela, un poste partagé où quelqu'un s'est trompé pénaliserait les
// collègues qui réussissent.
func TestSuccèsEfface(t *testing.T) {
	réinitialiser()

	for i := 0; i <= SeuilÉchecs+2; i++ {
		EnregistrerÉchec("10.0.0.3", "carol")
	}
	if ok, _ := BindAutorisé("10.0.0.3", "carol"); ok {
		t.Fatal("devrait être bloqué")
	}

	EnregistrerSuccès("10.0.0.3", "carol")
	if ok, _ := BindAutorisé("10.0.0.3", "carol"); !ok {
		t.Error("toujours bloqué après un succès")
	}
}

// TestDélaiPlafonné : le délai croît mais reste borné.
//
// Un doublement non plafonné dépasse la durée d'un entier après une trentaine
// d'échecs, ce qui bloquerait le compte définitivement — donc offrirait un déni
// de service à qui se trompe volontairement.
func TestDélaiPlafonné(t *testing.T) {
	réinitialiser()

	for i := 0; i < 100; i++ {
		EnregistrerÉchec("10.0.0.4", "dave")
	}
	_, reste := BindAutorisé("10.0.0.4", "dave")
	if reste > DélaiMaximum {
		t.Errorf("délai = %s, plafond %s", reste, DélaiMaximum)
	}
	if reste <= 0 {
		t.Errorf("délai = %s, attendu positif", reste)
	}
}
