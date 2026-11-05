package cluster

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
)

// La purge d'un core en maintenance (TO-DO 147), sans réseau ni horloge.

type registreSimule struct {
	machines []string
	ouvertes map[string]bool
	// partiesApresPrevenir : sessions qui basculent d'elles-mêmes à la 04_17.
	partiesApresPrevenir []string
	fermeesParPurge      []string
}

func (r *registreSimule) MachinesConnectees() []string { return r.machines }
func (r *registreSimule) IDs() []string {
	var out []string
	for id, ok := range r.ouvertes {
		if ok {
			out = append(out, id)
		}
	}
	return out
}
func (r *registreSimule) Fermer(id string) bool {
	if !r.ouvertes[id] {
		return false
	}
	r.ouvertes[id] = false
	r.fermeesParPurge = append(r.fermeesParPurge, id)
	return true
}

type horloge struct {
	total  time.Duration
	pauses []time.Duration
}

func (h *horloge) dormir(d time.Duration) { h.total += d; h.pauses = append(h.pauses, d) }

func TestLaPurgePrevientPuisFermeCeQuiResteEnEtalant(t *testing.T) {
	r := &registreSimule{
		machines: []string{"pc-1", "pc-2", "pc-3"},
		ouvertes: map[string]bool{"t1": true, "t2": true, "t3": true, "u1": true, "p1": true},
		// pc-1 et pc-2 basculent d'eux-mêmes ; pc-3 (agent ancien) reste.
		partiesApresPrevenir: []string{"t1", "t2"},
	}
	var prevenues []string
	h := &horloge{}
	p := purgeur{
		sessions: r,
		prevenir: func(m, motif string) (bool, error) {
			prevenues = append(prevenues, m)
			return true, nil
		},
		dormir: func(d time.Duration) {
			// Pendant la grâce, les agents qui savent basculer partent.
			if d == GracePurge {
				for _, id := range r.partiesApresPrevenir {
					r.ouvertes[id] = false
				}
			}
			h.dormir(d)
		},
		grace: GracePurge,
	}

	b := p.purger(60*time.Second, "maintenance du core core-1")

	if len(prevenues) != 3 || b.Prevenues != 3 {
		t.Fatalf("machines prévenues : %v (%d)", prevenues, b.Prevenues)
	}
	// Restent t3, u1, p1 : fermées par la purge. t1, t2 ne sont PAS comptées —
	// elles sont parties d'elles-mêmes.
	if b.Fermees != 3 || len(r.fermeesParPurge) != 3 {
		t.Fatalf("fermées par la purge : %v (%d)", r.fermeesParPurge, b.Fermees)
	}
	// La grâce d'abord, puis deux pauses de 20 s entre trois fermetures : le
	// reste est étalé sur la durée demandée, pas fermé d'un coup.
	attendu := fmt.Sprint([]time.Duration{GracePurge, 20 * time.Second, 20 * time.Second})
	if fmt.Sprint(h.pauses) != attendu {
		t.Errorf("pauses = %v, attendu %s", h.pauses, attendu)
	}
}

// Rien à prévenir : pas de grâce inutile ; rien à fermer : rien.
func TestUnCoreVideNAttendRien(t *testing.T) {
	h := &horloge{}
	p := purgeur{sessions: &registreSimule{ouvertes: map[string]bool{}},
		prevenir: func(string, string) (bool, error) { return true, nil }, dormir: h.dormir, grace: GracePurge}
	if b := p.purger(time.Minute, "x"); b != (BilanPurge{}) || h.total != 0 {
		t.Fatalf("core vide : %+v, attendu %v", b, h.total)
	}
}

// Une 04_17 non remise n'arrête pas la purge : la fermeture rattrape.
func TestUneMachineInjoignableEstFermeeQuandMeme(t *testing.T) {
	r := &registreSimule{machines: []string{"pc-1"}, ouvertes: map[string]bool{"t1": true}}
	p := purgeur{sessions: r,
		prevenir: func(string, string) (bool, error) { return false, fmt.Errorf("envoi impossible") },
		dormir:   func(time.Duration) {}, grace: GracePurge}
	if b := p.purger(time.Minute, "x"); b.Prevenues != 0 || b.Fermees != 1 {
		t.Fatalf("bilan = %+v", b)
	}
}

// Une session qui part d'elle-même PENDANT l'étalement — un agent qui bascule
// en retard — n'est pas comptée comme fermée par la purge.
func TestUneSessionPartieSeuleNEstPasComptee(t *testing.T) {
	r := &registreSimule{ouvertes: map[string]bool{"a": true, "b": true, "c": true}}
	premierePause := true
	p := purgeur{sessions: r,
		prevenir: func(string, string) (bool, error) { return false, nil },
		dormir: func(time.Duration) {
			if premierePause {
				// Pendant la première pause, toutes les sessions encore ouvertes
				// partent d'elles-mêmes.
				for id, ok := range r.ouvertes {
					if ok {
						r.ouvertes[id] = false
					}
				}
				premierePause = false
			}
		}, grace: GracePurge}
	b := p.purger(time.Minute, "x")
	if b.Fermees != 1 {
		t.Fatalf("fermées = %d, attendu 1 : les deux autres sont parties seules", b.Fermees)
	}
}

// --- part d'un core dans la purge d'un proxy (TO-DO 176) ---------------------------

func TestChaqueCoreNeFaitQuUneFoisSaPartDUnePurgeDeProxy(t *testing.T) {
	demandee := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	p := clusterdatabase.PurgeDeProxy{Hostname: "proxy-t176", Proprietaire: "owner-t176",
		Adresses: []string{"172.18.0.4"}, Demandee: demandee, Etalement: time.Second}

	l, te, vu, ex := lirePurgesDeProxies, terminerPart, vueDuProxy, executerPart
	t.Cleanup(func() { lirePurgesDeProxies, terminerPart, vueDuProxy, executerPart = l, te, vu, ex })

	lirePurgesDeProxies = func(*sql.DB) ([]clusterdatabase.PurgeDeProxy, error) {
		return []clusterdatabase.PurgeDeProxy{p}, nil
	}
	var parts []int
	terminerPart = func(_ *sql.DB, h string, d time.Time, n int) error {
		if h != p.Hostname || !d.Equal(demandee) {
			t.Errorf("part écrite pour %s / %v", h, d)
		}
		parts = append(parts, n)
		return nil
	}
	lancees := 0
	vueDuProxy = func(clusterdatabase.PurgeDeProxy) registrePurge {
		lancees++
		return &registreSimule{ouvertes: map[string]bool{"a1": true, "a2": true}}
	}
	// Exécution synchrone, et sans 04_17 réelle : le registre simulé n'a pas
	// de machine, donc ni prévenir ni grâce.
	executerPart = func(f func()) { f() }

	node := clusterstorage.Node{Hostname: "core-1"}
	lancerPurgesDeProxies(nil, node)
	lancerPurgesDeProxies(nil, node) // battement suivant : même demande
	if lancees != 1 || len(parts) != 1 || parts[0] != 2 {
		t.Fatalf("parts : %d lancée(s), écrites %v — attendu une seule, de 2", lancees, parts)
	}

	// Une NOUVELLE demande sur le même proxy est faite.
	p.Demandee = demandee.Add(time.Minute)
	demandee = p.Demandee
	lancerPurgesDeProxies(nil, node)
	if lancees != 2 {
		t.Errorf("une nouvelle demande n'a pas été exécutée")
	}
}

func TestUnePartDejaEnCoursNEstPasRelancee(t *testing.T) {
	p := clusterdatabase.PurgeDeProxy{Hostname: "proxy-encours", Demandee: time.Now()}
	partsEnCours.Store(p.Hostname, true)
	t.Cleanup(func() { partsEnCours.Delete(p.Hostname) })
	if aFaire(p) {
		t.Error("une part déjà en cours a été relancée")
	}
}

// TO-DO 216 : la 04_17 d'une purge nomme le nœud à quitter.
func TestLaPurgePrevientEnNommantLeNoeud(t *testing.T) {
	avant := actualiser
	t.Cleanup(func() { actualiser = avant })
	var recu []string
	actualiser = func(machine, motif string, quitter ...string) (bool, error) {
		recu = append([]string{machine, motif}, quitter...)
		return true, nil
	}
	ok, err := prevenirEnQuittant([]string{"192.168.56.10:6668"})("pc-a", "maintenance du proxy prx01")
	if !ok || err != nil || strings.Join(recu, "|") != "pc-a|maintenance du proxy prx01|192.168.56.10:6668" {
		t.Errorf("reçu %q (%v, %v)", recu, ok, err)
	}
}
