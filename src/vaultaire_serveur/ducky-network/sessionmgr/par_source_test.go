package sessionmgr

import (
	"net"
	"reflect"
	"testing"

	"vaultaire/core/storage"
)

// La vue par adresse source (TO-DO 176), sur un vrai registre.

type connSimulee struct {
	net.Conn
	distante string
	fermee   bool
}

func (c *connSimulee) RemoteAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", c.distante)
	return a
}
func (c *connSimulee) Close() error { c.fermee = true; return nil }

func ajouter(m *Manager, id, distante, machine, compte string, statut SessionStatus) *connSimulee {
	c := &connSimulee{distante: distante}
	m.AddOrUpdate(id, c, statut, &storage.DuckySession{SessionID: id})
	m.SetIdentity(id, compte, machine)
	return c
}

func TestLaVueParSourceNeGardeQueCeQuiArriveParLeProxy(t *testing.T) {
	m := NewManager()
	ajouter(m, "ctl", "172.18.0.4:40000", "proxy-1", CompteMachine, SessionAuthenticated) // le proxy lui-même
	ajouter(m, "a1", "172.18.0.4:40001", "pc-a", CompteMachine, SessionAuthenticated)
	ajouter(m, "a2", "172.18.0.4:40002", "pc-a", CompteMachine, SessionAuthenticated) // --fetch-key
	ajouter(m, "b1", "192.0.2.7:40003", "pc-b", CompteMachine, SessionAuthenticated)  // adresse vue
	ajouter(m, "h1", "172.18.0.4:40004", "", "", SessionPending)                      // poignée de main
	direct := ajouter(m, "d1", "10.0.0.50:40005", "pc-d", CompteMachine, SessionAuthenticated)

	v := m.VueParSource([]string{"172.18.0.4", "192.0.2.7"}, "PROXY-1")
	if got := v.MachinesConnectees(); !reflect.DeepEqual(got, []string{"pc-a", "pc-b"}) {
		t.Errorf("machines relayées : %v", got)
	}
	if got := v.IDs(); !reflect.DeepEqual(got, []string{"a1", "a2", "b1", "h1"}) {
		t.Errorf("sessions relayées : %v", got)
	}
	if v.Fermer("d1") || direct.fermee {
		t.Error("une session directe a été fermée par la purge du proxy")
	}
	if v.Fermer("ctl") {
		t.Error("la session du proxy lui-même a été fermée")
	}
	if !v.Fermer("a1") {
		t.Error("une session relayée n'a pas été fermée")
	}
	if _, ok := m.GetBySessionID("ctl"); !ok {
		t.Error("la session de contrôle du proxy a disparu")
	}
}

func TestSansAdresseLaVueEstVide(t *testing.T) {
	m := NewManager()
	ajouter(m, "a1", "172.18.0.4:40001", "pc-a", CompteMachine, SessionAuthenticated)
	v := m.VueParSource(nil, "proxy-1")
	if len(v.IDs()) != 0 || len(v.MachinesConnectees()) != 0 || v.Fermer("a1") {
		t.Error("sans adresse, la vue n'est pas vide : tout le core serait purgé")
	}
}

func TestAdressesDeRendLaSourceDuProxy(t *testing.T) {
	m := NewManager()
	ajouter(m, "ctl", "198.51.100.2:40000", "proxy-1", CompteMachine, SessionAuthenticated)
	ajouter(m, "a1", "172.18.0.4:40001", "pc-a", CompteMachine, SessionAuthenticated)
	if got := m.AdressesDe("Proxy-1"); !reflect.DeepEqual(got, []string{"198.51.100.2"}) {
		t.Errorf("AdressesDe = %v", got)
	}
}
