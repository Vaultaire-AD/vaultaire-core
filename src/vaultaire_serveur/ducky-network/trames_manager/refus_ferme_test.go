package tramesmanager

import (
	"net"
	"testing"
	"time"

	"vaultaire/core/storage"
	autc "vaultaire/ducky-network/authentification/client"
	"vaultaire/ducky-network/sessionmgr"
)

// ouvert dit si un socket accepte encore une écriture.
func ouvert(c net.Conn) bool {
	_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := c.Write([]byte{0})
	if err == nil {
		return true
	}
	ne, ok := err.(net.Error)
	return ok && ne.Timeout() // personne ne lit, mais le socket est là
}

func sessionDEssai(t *testing.T, id string, statut sessionmgr.SessionStatus) (*storage.DuckySession, net.Conn) {
	t.Helper()
	poste, core := net.Pipe()
	ds := &storage.DuckySession{Conn: core, SessionID: id}
	sessionmgr.Sessions.AddOrUpdate(id, core, statut, ds)
	t.Cleanup(func() {
		sessionmgr.Sessions.RemoveSession(id)
		poste.Close()
		core.Close()
	})
	return ds, poste
}

// Le core ferme la connexion d'une authentification refusée — TO-DO 159.
//
// C'était le poste qui la fermait, en paniquant sur la lecture du refus. Un
// agent antérieur ne panique plus devant un refus bien formé : sans ceci, la
// session resterait ouverte jusqu'au balayage des poignées de main.
func TestLeCoreFermeLaConnexionDUneAuthentificationRefusee(t *testing.T) {
	ds, _ := sessionDEssai(t, "refus-en-attente", sessionmgr.SessionPending)
	fermerApresRefus(autc.Refus("refus-en-attente", "alice", autc.MotifIdentifiants), ds)
	if ouvert(ds.Conn) {
		t.Fatal("la connexion d'une authentification refusée est restée ouverte")
	}
}

// Un refus qui n'est pas celui de la session — elle est déjà authentifiée :
// c'est le tunnel d'une machine — ne la ferme pas.
func TestLeCoreNeFermePasUnTunnelAuthentifie(t *testing.T) {
	ds, _ := sessionDEssai(t, "refus-tunnel", sessionmgr.SessionAuthenticated)
	fermerApresRefus(autc.Refus("refus-tunnel", "vaultaire", autc.MotifNonAuthentifie), ds)
	if !ouvert(ds.Conn) {
		t.Fatal("un tunnel authentifié a été fermé par un refus")
	}
}

// Toute autre réponse laisse la connexion ouverte : le défi, l'acceptation.
func TestLeCoreNeFermeQueSurUnRefus(t *testing.T) {
	ds, _ := sessionDEssai(t, "pas-un-refus", sessionmgr.SessionPending)
	for _, reponse := range []string{
		"02_02\nserveur_central\npas-un-refus\nid\njeton",
		autc.Acceptation("pas-un-refus", "alice", false, "empty"),
		"",
	} {
		fermerApresRefus(reponse, ds)
		if !ouvert(ds.Conn) {
			t.Fatalf("connexion fermée après une réponse qui n'est pas un refus : %q", reponse)
		}
	}
	fermerApresRefus("x", nil) // sans session : rien, et pas de panique
}
