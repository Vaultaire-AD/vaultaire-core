package cluster

import (
	"fmt"
	"testing"
	"time"
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
