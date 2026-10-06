package sessionmgr

import (
	"testing"
	"time"

	"vaultaire/core/reglages"
)

// Le balayage, à toutes les cadences que le réglage admet (TO-DO 110).
//
// reglages éprouve la formule ; ici, c'est StaleSessions elle-même qui reçoit
// la tolérance calculée, sur un registre garni comme il l'est au moment où le
// balayage passe : juste après l'envoi du battement, donc avec une cadence de
// silence sur chaque session saine.

func registreAuMomentDuBalayage(cadence time.Duration) *Manager {
	maintenant := time.Now()
	m := &Manager{sessions: map[string]*Session{}}
	poser := func(id string, statut SessionStatus, silence time.Duration) {
		m.sessions[id] = &Session{SessionID: id, Status: statut, LastSeen: maintenant.Add(-silence)}
	}
	// A répondu au battement précédent : une cadence de silence, à peine plus.
	poser("saine", SessionAuthenticated, cadence+20*time.Second)
	// A manqué UN battement : deux cadences.
	poser("un-battement-perdu", SessionAuthenticated, 2*cadence+20*time.Second)
	// Éteinte depuis longtemps.
	poser("partie", SessionAuthenticated, 3*cadence+2*time.Minute)
	// N'a jamais terminé sa poignée de main.
	poser("muette", SessionPending, 2*time.Minute)
	poser("en-cours", SessionPending, 5*time.Second)
	return m
}

func TestLeBalayageNeCoupePasUnParcSainQuelleQueSoitLaCadence(t *testing.T) {
	for _, minutes := range []int{1, 2, 5, 6, 10, 11, 30, 60} {
		cadence := time.Duration(minutes) * time.Minute
		m := registreAuMomentDuBalayage(cadence)

		fermees := map[string]bool{}
		for _, s := range m.StaleSessions(reglages.ToleranceDeSilencePour(cadence), time.Minute) {
			fermees[s.SessionID] = true
		}

		if fermees["saine"] {
			t.Errorf("cadence %d min : la session saine est coupée — c'est le défaut du point 110", minutes)
		}
		if fermees["un-battement-perdu"] {
			t.Errorf("cadence %d min : un seul battement perdu suffit à couper", minutes)
		}
		if !fermees["partie"] {
			t.Errorf("cadence %d min : une machine partie n'est jamais retirée", minutes)
		}
		if !fermees["muette"] || fermees["en-cours"] {
			t.Errorf("cadence %d min : le délai des poignées de main a bougé avec la cadence (%v)", minutes, fermees)
		}
	}
}

// La démonstration du défaut : avec l'ancienne constante de cinq minutes, une
// cadence de six coupe la session saine. Si ce test cesse de le montrer, c'est
// que le registre d'essai ne ressemble plus à un vrai balayage.
func TestLAncienneConstanteCoupaitLeParc(t *testing.T) {
	m := registreAuMomentDuBalayage(6 * time.Minute)
	for _, s := range m.StaleSessions(5*time.Minute, time.Minute) {
		if s.SessionID == "saine" {
			return
		}
	}
	t.Fatal("l'ancienne tolérance de cinq minutes ne coupe pas la session saine à six minutes de cadence : " +
		"le registre d'essai ne reproduit plus le constat")
}

// Le balayage propre aux poignées de main ne touche jamais une session
// authentifiée, si ancienne soit-elle : il passe toutes les trente secondes,
// bien plus souvent que le battement.
func TestLeBalayageDesPoigneesIgnoreLesSessionsAuthentifiees(t *testing.T) {
	m := registreAuMomentDuBalayage(60 * time.Minute)
	const jamais = time.Duration(1<<63 - 1)
	for _, s := range m.StaleSessions(jamais, time.Minute) {
		if s.Status == SessionAuthenticated {
			t.Fatalf("session authentifiée %q rendue par le balayage des poignées de main", s.SessionID)
		}
	}
}
