package enligne

import (
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage/stosession"
)

// À aucune cadence admise le client ne doit fermer un tunnel sain (TO-DO 110).
// Entre deux cycles de GPO, le seul trafic est le 02_11 du core : le silence
// d'un tunnel sain vaut une cadence, plus la minute du pas de nettoyage.
func TestAucuneCadenceNeFermeUnTunnelSain(t *testing.T) {
	for m := CadenceMinimum; m <= CadenceMaximum; m++ {
		c := time.Duration(m) * time.Minute
		delai := DelaiDeFermeturePour(c)
		if silence := c + time.Minute; silence >= delai {
			t.Errorf("cadence %d min : %s de silence sur un tunnel sain, fermeture à %s — "+
				"tout le parc se reconnecterait en boucle", m, silence, delai)
		}
		if silence := 2*c + 30*time.Second; silence >= delai {
			t.Errorf("cadence %d min : un seul battement perdu ferme le tunnel (%s ≥ %s)", m, silence, delai)
		}
	}
}

// L'ancienne constante, pour mémoire : à dix minutes de cadence, elle fermait.
func TestLAncienDelaiFermaitADixMinutes(t *testing.T) {
	if silence := 10*time.Minute + time.Minute; silence <= PlancherDelaiDeFermeture {
		t.Fatal("le constat du point 110 ne se reproduit plus : revoir ce test")
	}
	if got := DelaiDeFermeturePour(2 * time.Minute); got != 10*time.Minute {
		t.Errorf("à la cadence par défaut le délai doit rester de 10 min, reçu %s", got)
	}
}

func TestLaCadenceEstLueEnQueueDeLaTrame(t *testing.T) {
	cas := []struct {
		contenu string
		attendu time.Duration
		ok      bool
	}{
		{"client_giveinformation\nonline:20", 20 * time.Minute, true},
		{"vaultaire\nclient_giveinformation\nonline:1", time.Minute, true},
		{"client_giveinformation\n  online: 60  \n", 60 * time.Minute, true},
		// Un core antérieur à la 2.2 : pas de ligne.
		{"client_giveinformation", 0, false},
		{"", 0, false},
		// Hors bornes ou illisible : ignoré, jamais appliqué.
		{"client_giveinformation\nonline:0", 0, false},
		{"client_giveinformation\nonline:100000", 0, false},
		{"client_giveinformation\nonline:-5", 0, false},
		{"client_giveinformation\nonline:vingt", 0, false},
	}
	for _, c := range cas {
		got, ok := Lire(c.contenu)
		if got != c.attendu || ok != c.ok {
			t.Errorf("Lire(%q) = %s, %v ; attendu %s, %v", c.contenu, got, ok, c.attendu, c.ok)
		}
	}
}

// Le délai du registre de sessions suit l'annonce, et ne bouge pas sans elle.
func TestLeDelaiDeFermetureSuitLAnnonce(t *testing.T) {
	oublier()
	t.Cleanup(oublier)

	Apprendre("client_giveinformation")
	if got := stosession.SessionsUser.Delai(); got != 10*time.Minute {
		t.Fatalf("sans annonce le délai doit rester de 10 min, reçu %s", got)
	}

	Apprendre("client_giveinformation\nonline:30")
	if got := stosession.SessionsUser.Delai(); got != 61*time.Minute {
		t.Fatalf("cadence de 30 min : délai %s, attendu 61 min", got)
	}
	if got := DelaiDeFermeture(); got != 61*time.Minute {
		t.Fatalf("DelaiDeFermeture() = %s, attendu 61 min", got)
	}

	// Une annonce illisible ne remet pas le défaut : elle ne touche à rien.
	Apprendre("client_giveinformation\nonline:n'importe quoi")
	if got := stosession.SessionsUser.Delai(); got != 61*time.Minute {
		t.Fatalf("une annonce illisible a changé le délai : %s", got)
	}

	// Le core revient à sa cadence par défaut : le délai redescend.
	Apprendre("client_giveinformation\nonline:2")
	if got := stosession.SessionsUser.Delai(); got != 10*time.Minute {
		t.Fatalf("retour à 2 min : délai %s, attendu 10 min", got)
	}
}

// Les capacités sont celles du core de la connexion COURANTE (TO-DO 141) : un
// proxy qui bascule sur un core resté en arrière doit cesser d'émettre les
// trames que ce core fermerait.
func TestLesCapacitesSuiventLeCoreCourant(t *testing.T) {
	oublier()
	t.Cleanup(oublier)

	if CoreSait(CapaciteRelais) {
		t.Fatal("capacité tenue pour acquise avant toute annonce")
	}

	Apprendre("vaultaire\nclient_giveinformation\nonline:2\ncapacites:relais")
	if !CoreSait(CapaciteRelais) {
		t.Fatal("capacité annoncée, non retenue")
	}

	// Un battement du même core : toujours là.
	Apprendre("client_giveinformation\nonline:2\ncapacites: Relais , autre")
	if !CoreSait(CapaciteRelais) || !CoreSait("autre") {
		t.Fatal("la liste se lit sans égard à la casse ni aux espaces")
	}

	// Reconnexion sur un core antérieur à la 2.2 : sa 02_11 n'a pas la ligne.
	Apprendre("vaultaire\nclient_giveinformation")
	if CoreSait(CapaciteRelais) {
		t.Fatal("capacité gardée d'un core précédent : le proxy émettrait une trame que celui-ci ferme")
	}
}
