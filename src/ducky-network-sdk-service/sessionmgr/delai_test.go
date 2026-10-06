package sessionmgr

import (
	"net"
	"testing"
	"time"
)

// Le nettoyage suit le délai courant, pas celui de la création (TO-DO 110).
func TestLeNettoyageSuitLeDelaiCourant(t *testing.T) {
	m := &Manager{sessions: map[string]*Session{}, timeout: 10 * time.Minute}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	maintenant := time.Now()
	// Un tunnel sain sous un core qui bat toutes les onze minutes : onze
	// minutes et demie de silence au moment du passage.
	m.sessions["tunnel"] = &Session{SessionID: "tunnel", Username: "vaultaire", Conn: a,
		LastSeen: maintenant.Add(-11*time.Minute - 30*time.Second)}

	// Le délai appris pour cette cadence : il survit.
	m.DefinirDelai(23 * time.Minute)
	m.fermerLesSessionsMuettes(maintenant)
	if _, la := m.sessions["tunnel"]; !la {
		t.Fatal("tunnel sain fermé alors que le délai a été relevé")
	}

	// Avec l'ancien délai fixe, il est fermé : c'est le défaut du point 110.
	m.DefinirDelai(10 * time.Minute)
	m.fermerLesSessionsMuettes(maintenant)
	if _, la := m.sessions["tunnel"]; la {
		t.Fatal("à dix minutes de délai, onze minutes de silence doivent fermer le tunnel")
	}

	// Une valeur nulle ne s'applique pas : elle fermerait tout.
	m.DefinirDelai(0)
	if m.Delai() != 10*time.Minute {
		t.Fatalf("un délai nul a été accepté : %s", m.Delai())
	}
}
