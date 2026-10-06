package sessionmgr

import (
	"testing"
	"time"

	"vaultaire/core/storage"
)

// À qui pousser une trame destinée à une machine (TO-DO 89).
//
// # Ce que ces tests gardent
//
// « gpo refresh » répondait « hors ligne » à une machine connectée : la
// session était choisie au hasard parmi toutes celles qui portaient son
// identifiant, poignées de main et sessions d'utilisateurs comprises. Chaque
// cas ci-dessous est une session qu'une vraie machine possède en même temps
// que son tunnel.

func inscrire(m *Manager, id, compte, machine string, statut SessionStatus, cree, vue time.Time, avecDucky bool) {
	var d *storage.DuckySession
	if avecDucky {
		d = &storage.DuckySession{SessionID: id}
	}
	m.sessions[id] = &Session{SessionID: id, Username: compte, ClientSoftwareID: machine,
		Status: statut, DuckySession: d, CreatedAt: cree, LastSeen: vue}
}

func ids(s []SessionMachine) []string {
	var out []string
	for _, x := range s {
		out = append(out, x.SessionID)
	}
	return out
}

func TestLeTunnelPasseAvantToutLeReste(t *testing.T) {
	m := NewManager()
	now := time.Now()
	inscrire(m, "poignee", CompteMachine, "PC-01", SessionPending, now, now, false)
	inscrire(m, "alice", "alice", "PC-01", SessionAuthenticated, now, now, true)
	inscrire(m, "fetchkey", CompteMachine, "PC-01", SessionAuthenticated, now, now, true)
	inscrire(m, "tunnel", CompteMachine, "PC-01", SessionAuthenticated, now.Add(-3*time.Hour), now.Add(-30*time.Second), true)
	inscrire(m, "echec", CompteMachine, "PC-01", SessionFailed, now, now, true)
	inscrire(m, "autre", CompteMachine, "PC-02", SessionAuthenticated, now.Add(-5*time.Hour), now, true)

	got := ids(m.SessionsMachine("PC-01", 5*time.Minute))
	if len(got) != 2 || got[0] != "tunnel" || got[1] != "fetchkey" {
		t.Fatalf("sessions = %v, attendu [tunnel fetchkey] : une poignée de main, la session "+
			"d'un utilisateur ou une session en échec ne reçoivent pas les trames de la machine, "+
			"et le tunnel — le plus ancien — passe avant une connexion de quelques secondes", got)
	}
}

func TestUnTunnelMortPasseApresLeVivant(t *testing.T) {
	m := NewManager()
	now := time.Now()
	// Coupure réseau : l'ancien tunnel reste inscrit jusqu'au balayage, la
	// machine s'est reconnectée par un nouveau.
	inscrire(m, "mort", CompteMachine, "PC-01", SessionAuthenticated, now.Add(-5*time.Hour), now.Add(-20*time.Minute), true)
	inscrire(m, "neuf", CompteMachine, "PC-01", SessionAuthenticated, now.Add(-10*time.Minute), now.Add(-time.Minute), true)

	got := ids(m.SessionsMachine("PC-01", 5*time.Minute))
	if len(got) != 2 || got[0] != "neuf" {
		t.Fatalf("sessions = %v : une écriture dans le tunnel mort « réussirait » dans un "+
			"tampon noyau, et le rafraîchissement serait perdu en se disant remis", got)
	}
}

func TestLaCasseNeDistinguePasLesMachines(t *testing.T) {
	m := NewManager()
	now := time.Now()
	inscrire(m, "tunnel", CompteMachine, "PC-01", SessionAuthenticated, now, now, true)

	got := m.SessionsMachine(" pc-01 ", time.Minute)
	if len(got) != 1 || got[0].ClientSoftwareID != "PC-01" {
		t.Fatalf("sessions = %+v : la base trouve « pc-01 » (collation _ci), le registre doit "+
			"le trouver aussi, et rendre la forme canonique", got)
	}
}

func TestAucuneSessionUtilisable(t *testing.T) {
	m := NewManager()
	now := time.Now()
	inscrire(m, "poignee", CompteMachine, "PC-01", SessionPending, now, now, false)
	if got := m.SessionsMachine("PC-01", time.Minute); len(got) != 0 {
		t.Fatalf("sessions = %v : une machine en pleine poignée de main n'est pas joignable", ids(got))
	}
	if got := m.SessionsMachine("", time.Minute); len(got) != 0 {
		t.Fatal("un identifiant vide a trouvé une session")
	}
}
