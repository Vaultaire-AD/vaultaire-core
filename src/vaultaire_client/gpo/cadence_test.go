package gpo

import (
	"testing"
	"time"

	"duckynetworkclient/V1/backoff"
)

// La cadence vient du réseau et pilote une boucle infinie : ces tests gardent
// les deux choses qui rendraient l'agent nuisible — une cadence absurde
// appliquée telle quelle, et une cadence perdue parce qu'elle n'était pas à la
// place attendue.

func remettreCadence(t *testing.T) {
	t.Helper()
	cadenceMu.Lock()
	cadence = MachineRefreshInterval
	cadenceMu.Unlock()
	// Les réveils déposés par les tests précédents fausseraient le suivant.
	select {
	case <-reveilCadence:
	default:
	}
}

func TestLaCadenceEstLueAQuelqueRangQueCeSoit(t *testing.T) {
	// 05_02 porte six champs de manifeste avant la cadence, 05_03 un seul :
	// chercher à un rang fixe marcherait pour l'une et raterait l'autre.
	cas := map[string][]string{
		"05_03": {"empreinte", PrefixeCadence + "15"},
		"05_02": {"3", "empreinte", "2", "4096", "7", "somme", PrefixeCadence + "15"},
	}
	for nom, lignes := range cas {
		remettreCadence(t)
		appliquerCadence(lignes)
		if got := CadenceActuelle(); got != 15*time.Minute {
			t.Errorf("%s : cadence %s, attendu 15m", nom, got)
		}
	}
}

func TestUneCadenceAbsurdeEstBornee(t *testing.T) {
	cas := []struct {
		ligne   string
		attendu time.Duration
	}{
		{PrefixeCadence + "0", CadenceMinimum},      // une boucle d'attente active
		{PrefixeCadence + "-30", CadenceMinimum},    // idem, par un autre chemin
		{PrefixeCadence + "1", CadenceMinimum},      // sous le minimum du réglage
		{PrefixeCadence + "100000", CadenceMaximum}, // la machine disparaîtrait du parc
	}
	for _, c := range cas {
		remettreCadence(t)
		appliquerCadence([]string{"empreinte", c.ligne})
		if got := CadenceActuelle(); got != c.attendu {
			t.Errorf("%q : cadence %s, attendu %s", c.ligne, got, c.attendu)
		}
	}
}

// Un core resté à l'ancienne version n'envoie pas la ligne. L'agent doit alors
// garder son défaut, et surtout ne pas la lire dans un champ voisin.
func TestSansLigneDeCadenceLeDefautEstConserve(t *testing.T) {
	remettreCadence(t)
	appliquerCadence([]string{"3", "empreinte", "2", "4096", "7", "somme"})
	if got := CadenceActuelle(); got != MachineRefreshInterval {
		t.Errorf("cadence %s, attendu le defaut %s", got, MachineRefreshInterval)
	}

	remettreCadence(t)
	appliquerCadence([]string{"empreinte", PrefixeCadence + "quinze"})
	if got := CadenceActuelle(); got != MachineRefreshInterval {
		t.Errorf("cadence illisible : %s, attendu le defaut %s", got, MachineRefreshInterval)
	}
}

// Une cadence changée doit réveiller la boucle, sinon elle n'entre en vigueur
// qu'au terme de l'ancienne attente — soit l'heure qu'on cherchait à éviter.
func TestUnChangementDeCadenceReveilleLaBoucle(t *testing.T) {
	remettreCadence(t)
	appliquerCadence([]string{PrefixeCadence + "10"})
	select {
	case <-reveilCadence:
	default:
		t.Fatal("aucun reveil depose apres un changement de cadence")
	}

	// La même valeur ne réveille rien : sinon chaque 05_03 d'un parc entier —
	// c'est-à-dire le cas le plus fréquent — relancerait la boucle.
	appliquerCadence([]string{PrefixeCadence + "10"})
	select {
	case <-reveilCadence:
		t.Fatal("une cadence inchangee a reveille la boucle")
	default:
	}
}

// Un cycle en échec ne doit pas coûter une cadence entière, et un nouvel essai
// ne doit jamais être plus espacé que le tour normal.
func TestUnCycleEnEchecReessayePlusTot(t *testing.T) {
	remettreCadence(t)
	echecs := backoff.New()

	for i := 0; i < 12; i++ {
		d := prochainDelai(false, echecs)
		if d > CadenceActuelle() {
			t.Fatalf("essai %d : attente %s, superieure a la cadence %s", i, d, CadenceActuelle())
		}
	}

	// Un cycle qui aboutit remet la suite à zéro : sans cela, la panne suivante
	// partirait du délai maximum.
	if d := prochainDelai(true, echecs); d != CadenceActuelle() {
		t.Fatalf("apres un cycle abouti : attente %s, attendu la cadence %s", d, CadenceActuelle())
	}
	if d := prochainDelai(false, echecs); d > backoff.DelaiInitial*2 {
		t.Fatalf("la suite de degressivite n'a pas ete remise a zero : %s", d)
	}
}
