package serveurcommunication

import (
	"sync/atomic"
	"testing"
	"time"
)

// Une panique dans la boucle ne doit pas arrêter la supervision.
func TestLaSupervisionRelanceApresPanique(t *testing.T) {
	var appels atomic.Int32
	// Drapeau ATOMIQUE, et non storage.Persistent : la boucle supervisée le lit
	// depuis sa propre goroutine pendant que le test l'écrit depuis la sienne.
	var persistant atomic.Bool
	persistant.Store(true)

	fini := make(chan struct{})
	ancienneBoucle, anciennePause, ancienPersistant := executerBoucle, pause, estPersistant
	defer func() { executerBoucle, pause, estPersistant = ancienneBoucle, anciennePause, ancienPersistant }()

	estPersistant = persistant.Load
	pause = func(time.Duration) {}
	executerBoucle = func() {
		n := appels.Add(1)
		switch {
		case n == 1:
			panic("trame inattendue")
		case n >= 3:
			persistant.Store(false)
			close(fini)
		}
	}

	// La fin de la supervision est ATTENDUE avant de rendre la main : les
	// variables remplacées ci-dessus sont restaurées au retour du test, et la
	// goroutine les lit encore tant qu'elle n'est pas sortie.
	termine := make(chan struct{})
	go func() { superviserTunnel(); close(termine) }()

	select {
	case <-fini:
	case <-time.After(2 * time.Second):
		t.Fatal("la boucle n'a pas été relancée après la panique")
	}
	select {
	case <-termine:
	case <-time.After(2 * time.Second):
		t.Fatal("la supervision ne s'arrête pas quand la persistance tombe")
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
