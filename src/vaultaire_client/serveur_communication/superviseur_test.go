package serveurcommunication

import (
	"sync/atomic"
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// Une panique dans la boucle ne doit pas arrêter la supervision.
func TestLaSupervisionRelanceApresPanique(t *testing.T) {
	var appels atomic.Int32
	fini := make(chan struct{})
	ancienneBoucle, anciennePause, ancienPersistent := executerBoucle, pause, storage.Persistent
	defer func() { executerBoucle, pause, storage.Persistent = ancienneBoucle, anciennePause, ancienPersistent }()

	storage.Persistent = true
	pause = func(time.Duration) {}
	executerBoucle = func() {
		n := appels.Add(1)
		switch {
		case n == 1:
			panic("trame inattendue")
		case n >= 3:
			storage.Persistent = false
			close(fini)
		}
	}

	go superviserTunnel()
	select {
	case <-fini:
	case <-time.After(2 * time.Second):
		t.Fatal("la boucle n'a pas été relancée après la panique")
	}
	if appels.Load() < 3 {
		t.Fatalf("%d lancements, au moins 3 attendus", appels.Load())
	}
}

// Deux demandes de démarrage ne lancent qu'une supervision.
func TestUnSeulTunnelParProcessus(t *testing.T) {
	var lancements atomic.Int32
	bloque := make(chan struct{})
	ancienneBoucle := executerBoucle
	defer func() { executerBoucle = ancienneBoucle; close(bloque) }()
	executerBoucle = func() { lancements.Add(1); <-bloque }

	tunnelDemarre.Store(false)
	for i := 0; i < 5; i++ {
		DemarrerTunnelMachine()
	}
	time.Sleep(50 * time.Millisecond)
	if n := lancements.Load(); n != 1 {
		t.Fatalf("%d boucles lancées, une seule attendue", n)
	}
}
