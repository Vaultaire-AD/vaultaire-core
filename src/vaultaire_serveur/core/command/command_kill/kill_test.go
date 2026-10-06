package commandkill

import (
	"strings"
	"testing"

	"vaultaire/core/revocation"
	revocationmanager "vaultaire/ducky-network/revocation_manager"
)

// TO-DO 133 — ce que la commande AFFIRME.
//
// L'aide de `kill -h` disait, sous « ce que fait le mode par défaut » : « ses
// sessions ouvertes sont fermées immédiatement ». C'était faux, et c'est
// l'endroit où un exploitant va chercher la vérité pendant un incident. Ces
// tests gardent les phrases, pas le code : une aide qui promet plus que ce que
// l'ordre fait est un défaut au même titre qu'un ordre qui ne fait rien.

func TestLAideDitCeQuiEstCoupeEtCeQuiNeLEstPasEncore(t *testing.T) {
	aide := helpText()

	for _, attendu := range []string{
		"verrouillé, PUIS",       // l'ordre des deux gestes
		"détaché d'un terminal",  // la décision : tmux et nohup tombent aussi
		"session ouverte",        // les cibles ne sont plus les seuls groupes
		"HORS LIGNE",             // ce qui n'est PAS immédiat
		"toutes les dix minutes", // le rappel du point 134
	} {
		if !strings.Contains(aide, attendu) {
			t.Errorf("l'aide ne dit plus %q", attendu)
		}
	}

	// La phrase d'origine, sans réserve : elle ne doit pas revenir. « Fermées
	// immédiatement » ne vaut que pour les sessions que le serveur tient.
	if strings.Contains(aide, "ses sessions ouvertes sont fermées immédiatement") {
		t.Error("l'aide affirme de nouveau que les sessions ouvertes sont fermees immediatement, " +
			"sans dire lesquelles ni sur quelles machines")
	}
}

func TestLeCompteRenduNeConfondPasRemisEtApplique(t *testing.T) {
	rendu := formatOutcome(revocationmanager.Outcome{
		OrderID: 12, Mode: revocation.ModeSoft, Username: "alice",
		TargetCount: 5, PushedNow: 3, SessionsKilled: 2,
		MachinesEnSession: 2, HorsGroupes: 1,
	})

	for _, attendu := range []string{
		"Sessions Vaultaire fermées (portail, Ducky) : 2",
		"Machines visées : 5 — dont 2 où une session du compte est ouverte",
		"1 visée(s) pour cette seule raison",
		"Ordre remis immédiatement : 3",
		"En attente (machines hors ligne) : 2",
		"kill -u alice --unlock",
	} {
		if !strings.Contains(rendu, attendu) {
			t.Errorf("le compte rendu ne porte pas %q :\n%s", attendu, rendu)
		}
	}
	for _, interdit := range []string{"Appliqué immédiatement", "  Sessions fermées :"} {
		if strings.Contains(rendu, interdit) {
			t.Errorf("le compte rendu dit encore %q : le core ne sait pas, a cet instant, "+
				"ce que les postes ont applique", interdit)
		}
	}
}

// Un déverrouillage ne coupe rien : le compte rendu ne doit pas le laisser croire.
func TestLeDeverrouillageNAnnonceAucuneCoupure(t *testing.T) {
	rendu := formatOutcome(revocationmanager.Outcome{
		OrderID: 13, Mode: revocation.ModeUnlock, Username: "alice", TargetCount: 2, PushedNow: 2,
	})
	if strings.Contains(rendu, "tue ses processus") {
		t.Errorf("un deverrouillage annonce une coupure :\n%s", rendu)
	}
}
