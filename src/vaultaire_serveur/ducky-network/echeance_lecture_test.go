package duckynetwork

import (
	"testing"
	"time"

	"vaultaire/core/netguard"
	"vaultaire/core/reglages"
)

// TestEcheanceDeLectureSuitLaTolerance fige le quatrième délai du TO-DO 110 :
// l'échéance de lecture d'une session authentifiée ne doit JAMAIS tomber avant
// que le balayage ne tolère plus la session.
//
// Elle valait dix minutes en dur. À toute cadence au-delà de dix, le core
// fermait donc lui-même chaque session saine entre deux battements — le défaut
// même que la tolérance calculée venait de retirer au balayage.
func TestEcheanceDeLectureSuitLaTolerance(t *testing.T) {
	for minutes := 1; minutes <= 60; minutes++ {
		cadence := time.Duration(minutes) * time.Minute
		tolerance := reglages.ToleranceDeSilencePour(cadence)
		echeance := echeanceDeLecture(true, tolerance)

		if echeance < tolerance {
			t.Errorf("cadence %s : échéance de lecture %s plus courte que la tolérance %s — "+
				"le socket serait fermé avant que le balayage n'ait conclu", cadence, echeance, tolerance)
		}
		// Une session saine ne dit rien entre deux battements : il faut au
		// moins une cadence entière, et la marge d'un battement perdu.
		if echeance < 2*cadence {
			t.Errorf("cadence %s : échéance de lecture %s, moins de deux battements", cadence, echeance)
		}
		if echeance < netguard.SessionReadTimeout {
			t.Errorf("cadence %s : échéance %s sous l'ancienne valeur %s — une mise à jour ne doit "+
				"raccourcir aucun délai", cadence, echeance, netguard.SessionReadTimeout)
		}
	}
}

// TestEcheanceDeLectureInchangeeAuxCadencesCourtes : à la cadence par défaut,
// rien ne bouge.
func TestEcheanceDeLectureInchangeeAuxCadencesCourtes(t *testing.T) {
	for _, minutes := range []int{1, 2, 3, 4} {
		tolerance := reglages.ToleranceDeSilencePour(time.Duration(minutes) * time.Minute)
		if got := echeanceDeLecture(true, tolerance); got != netguard.SessionReadTimeout {
			t.Errorf("cadence %d min : échéance %s, attendu %s", minutes, got, netguard.SessionReadTimeout)
		}
	}
}

// TestEcheanceDeLectureDUnePoigneeDeMain : la tolérance ne s'applique JAMAIS à
// une connexion qui n'a pas ouvert son canal. Si elle le faisait, allonger la
// cadence offrirait un socket à quiconque ouvre une connexion sans rien dire.
func TestEcheanceDeLectureDUnePoigneeDeMain(t *testing.T) {
	for _, tolerance := range []time.Duration{0, 5 * time.Minute, 121 * time.Minute} {
		if got := echeanceDeLecture(false, tolerance); got != netguard.HandshakeReadTimeout {
			t.Errorf("tolérance %s : échéance d'une poignée de main %s, attendu %s (fixe)",
				tolerance, got, netguard.HandshakeReadTimeout)
		}
	}
}
