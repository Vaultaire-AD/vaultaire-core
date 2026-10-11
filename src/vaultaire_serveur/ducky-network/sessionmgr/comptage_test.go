package sessionmgr

import "testing"

// Le comptage publié avec le battement du core (TO-DO 148).
func TestCompter(t *testing.T) {
	m := NewManager()
	ajouter := func(id, compte, machine string, statut SessionStatus) {
		m.sessions[id] = &Session{SessionID: id, Username: compte, ClientSoftwareID: machine, Status: statut}
	}
	ajouter("t1", CompteMachine, "PC-01", SessionAuthenticated)
	ajouter("t2", CompteMachine, "pc-01", SessionAuthenticated) // --fetch-key, même machine
	ajouter("t3", CompteMachine, "pc-02", SessionAuthenticated)
	ajouter("t4", CompteMachine, "", SessionAuthenticated) // identité absente : un tunnel, aucune machine
	ajouter("u1", "alice.martin@acme.lan", "pc-01", SessionAuthenticated)
	ajouter("p1", "", "", SessionPending)
	ajouter("p2", CompteMachine, "pc-03", SessionPending) // annoncé, pas authentifié
	ajouter("f1", "bob", "pc-02", SessionFailed)

	got := m.Compter()
	want := Comptage{Machines: 2, Tunnels: 4, Comptes: 1, Poignees: 2}
	if got != want {
		t.Fatalf("Compter() = %+v, attendu %+v — la charge publiée du core serait fausse", got, want)
	}
	if (NewManager()).Compter() != (Comptage{}) {
		t.Fatal("un registre vide doit compter zéro partout")
	}
}

// Fermer dit si la session était là : la purge ne compte pas ce qui est parti
// de soi-même.
func TestFermerEtIDs(t *testing.T) {
	m := NewManager()
	m.sessions["a"] = &Session{SessionID: "a"}
	m.sessions["b"] = &Session{SessionID: "b"}
	if ids := m.IDs(); len(ids) != 2 {
		t.Fatalf("IDs = %v", ids)
	}
	if !m.Fermer("a") || m.Fermer("a") || m.Fermer("inconnue") {
		t.Fatal("Fermer doit rendre vrai une fois, puis faux")
	}
	if m.Count() != 1 {
		t.Fatalf("reste %d session(s)", m.Count())
	}
}
