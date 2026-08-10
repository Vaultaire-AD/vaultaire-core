package ratelimit

import (
	"testing"
	"time"
)

// avancer déplace l'horloge du paquet, et rend de quoi la remettre.
//
// Sans cela, éprouver l'oubli demanderait d'attendre un quart d'heure et le
// plafond, une demi-minute : le test deviendrait le poste le plus lent de la
// suite, donc celui qu'on finit par ne plus lancer.
func avancer(t *testing.T) func(time.Duration) {
	t.Helper()
	base := time.Now()
	decalage := time.Duration(0)
	maintenant = func() time.Time { return base.Add(decalage) }
	t.Cleanup(func() { maintenant = time.Now })
	return func(d time.Duration) { decalage += d }
}

// TestSeuilPuisDelai : les essais gratuits passent, le dépassement freine.
//
// Un utilisateur qui se trompe une ou deux fois ne doit rien sentir ; un
// balayage doit ralentir.
func TestSeuilPuisDelai(t *testing.T) {
	Reinitialiser()
	avancer(t)

	for i := 0; i < EssaisGratuits; i++ {
		Echec("alice", "10.0.0.1")
		if ok, _ := Autorise("alice", "10.0.0.1"); !ok {
			t.Fatalf("freiné dès le %dᵉ échec, alors que le quota gratuit est %d", i+1, EssaisGratuits)
		}
	}

	Echec("alice", "10.0.0.1")
	ok, reste := Autorise("alice", "10.0.0.1")
	if ok {
		t.Fatal("non freiné après dépassement du quota gratuit")
	}
	if reste <= 0 || reste > DelaiBase {
		t.Errorf("échéance restante = %s, attendue dans ]0, %s]", reste, DelaiBase)
	}
}

// TestDelaiDouble : chaque échec supplémentaire double l'échéance.
func TestDelaiDouble(t *testing.T) {
	Reinitialiser()
	horloge := avancer(t)

	for i := 0; i <= EssaisGratuits; i++ {
		Echec("bob", "10.0.0.2")
	}

	attendus := []time.Duration{DelaiBase, 2 * DelaiBase, 4 * DelaiBase}
	for i, attendu := range attendus {
		_, reste := Autorise("bob", "10.0.0.2")
		if reste != attendu {
			t.Errorf("échec %d : échéance = %s, attendue %s", EssaisGratuits+1+i, reste, attendu)
		}
		// On laisse passer l'échéance avant de recompter, sinon l'échec suivant
		// serait un essai que la limitation aurait refusé.
		horloge(attendu)
		Echec("bob", "10.0.0.2")
	}
}

// TestDelaiPlafonne : l'échéance croît mais reste bornée.
//
// Un doublement non plafonné dépasse la capacité d'un int64 dès la quarantaine
// d'échecs et devient NÉGATIF, puis nul quand le décalage atteint 64 bits.
// L'échéance serait alors dans le passé et la limitation, muette. C'est le mode
// de panne le plus vicieux de ce type de code : elle disparaît exactement quand
// on en a besoin.
func TestDelaiPlafonne(t *testing.T) {
	Reinitialiser()
	avancer(t)

	for i := 0; i < 200; i++ {
		Echec("dave", "10.0.0.4")
	}
	_, reste := Autorise("dave", "10.0.0.4")
	if reste <= 0 {
		t.Fatalf("échéance = %s, attendue positive — débordement du décalage", reste)
	}
	if reste > DelaiMaximum {
		t.Errorf("échéance = %s, plafond %s", reste, DelaiMaximum)
	}
}

// TestDeuxAxesIndependants : le compte et la source comptent séparément.
//
// Compter uniquement par source laisse passer un botnet ; uniquement par compte,
// un balayage de comptes depuis une seule machine.
func TestDeuxAxesIndependants(t *testing.T) {
	Reinitialiser()
	avancer(t)

	// Une seule source, des comptes tous différents : l'axe SOURCE doit freiner.
	for i := 0; i <= EssaisGratuits; i++ {
		Echec(string(rune('a'+i)), "10.0.0.5")
	}
	if ok, _ := Autorise("personne", "10.0.0.5"); ok {
		t.Error("balayage de comptes depuis une même source non freiné")
	}

	Reinitialiser()

	// Un seul compte, des sources toutes différentes : l'axe COMPTE doit freiner.
	for i := 0; i <= EssaisGratuits; i++ {
		Echec("carol", "10.0.1."+string(rune('0'+i)))
	}
	if ok, _ := Autorise("carol", "192.168.0.1"); ok {
		t.Error("balayage de mots de passe depuis plusieurs sources non freiné")
	}
}

// TestRefusNeComptePas : une tentative refusée n'aggrave pas la sanction.
//
// Sinon un client mal configuré qui réessaie en boucle s'enfermerait tout seul,
// et il suffirait de marteler la porte pour maintenir le compte d'un tiers hors
// d'usage indéfiniment.
func TestRefusNeComptePas(t *testing.T) {
	Reinitialiser()
	avancer(t)

	for i := 0; i <= EssaisGratuits; i++ {
		Echec("erin", "10.0.0.6")
	}
	_, avant := Autorise("erin", "10.0.0.6")
	for i := 0; i < 50; i++ {
		Autorise("erin", "10.0.0.6")
	}
	_, apres := Autorise("erin", "10.0.0.6")
	if apres > avant {
		t.Errorf("échéance passée de %s à %s après 50 tentatives refusées", avant, apres)
	}
}

// TestSuccesEfface : une authentification réussie remet les deux compteurs à
// zéro.
//
// Les DEUX : sans cela, un poste partagé où quelqu'un s'est trompé pénaliserait
// les collègues qui réussissent.
func TestSuccesEfface(t *testing.T) {
	Reinitialiser()
	avancer(t)

	for i := 0; i <= EssaisGratuits+2; i++ {
		Echec("frank", "10.0.0.7")
	}
	if ok, _ := Autorise("frank", "10.0.0.7"); ok {
		t.Fatal("devrait être freiné")
	}

	Reussite("frank", "10.0.0.7")
	if ok, _ := Autorise("frank", "10.0.0.7"); !ok {
		t.Error("toujours freiné après un succès")
	}
	if c, s := Etat("frank", "10.0.0.7"); c != 0 || s != 0 {
		t.Errorf("compteurs résiduels après succès : compte=%d source=%d", c, s)
	}
}

// TestOubli : après la fenêtre sans échec, le compteur repart de zéro.
//
// Sans oubli, un compte accumulerait ses erreurs sur des mois et finirait
// plafonné pour une faute de frappe faite en mars.
func TestOubli(t *testing.T) {
	Reinitialiser()
	horloge := avancer(t)

	for i := 0; i <= EssaisGratuits+3; i++ {
		Echec("grace", "10.0.0.8")
	}
	horloge(Oubli + time.Second)

	if ok, _ := Autorise("grace", "10.0.0.8"); !ok {
		t.Fatal("encore freiné après la fenêtre d'oubli")
	}
	Echec("grace", "10.0.0.8")
	if c, _ := Etat("grace", "10.0.0.8"); c != 1 {
		t.Errorf("compteur = %d après oubli, attendu 1 : les échecs anciens n'ont pas été effacés", c)
	}
}

// TestPurge : les entrées oisives quittent les tables.
//
// Sans purge, chaque nom d'utilisateur inventé et chaque source laisserait une
// entrée définitive : un attaquant obtiendrait une fuite de mémoire pour le prix
// d'une requête.
func TestPurge(t *testing.T) {
	Reinitialiser()
	horloge := avancer(t)

	for i := 0; i < 500; i++ {
		Echec("inconnu"+string(rune('A'+i%26))+string(rune('a'+i/26)), "10.0.0.9")
	}
	horloge(2*Oubli + time.Second)

	// Autorise déclenche la purge amortie.
	Autorise("heidi", "10.0.0.10")

	mu.Lock()
	restants := len(parCompte)
	mu.Unlock()
	if restants != 0 {
		t.Errorf("%d compteurs de compte survivent à la purge", restants)
	}
}

// TestCleVideIgnoree : une clé vide ne crée pas de compteur.
//
// Un nom d'utilisateur absent ou une source indéterminable rassembleraient
// sinon toutes les tentatives sous la même clé « », et le premier balayage venu
// freinerait tout le monde.
func TestCleVideIgnoree(t *testing.T) {
	Reinitialiser()
	avancer(t)

	for i := 0; i < 20; i++ {
		Echec("", "")
	}
	if ok, _ := Autorise("", ""); !ok {
		t.Error("la clé vide a été comptée")
	}
}
