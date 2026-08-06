package netguard

import (
	"net"
	"sync"
	"testing"
)

// faussePaire rend une connexion dont l'adresse distante est celle demandée.
type fausseConn struct {
	net.Conn
	addr net.Addr
}

func (c fausseConn) RemoteAddr() net.Addr { return c.addr }

type fausseAddr string

func (a fausseAddr) Network() string { return "tcp" }
func (a fausseAddr) String() string  { return string(a) }

func conn(hôte string) net.Conn {
	return fausseConn{addr: fausseAddr(hôte + ":54321")}
}

// TestPlafondParAdresse : une source ne peut pas prendre toutes les places.
//
// C'est l'intérêt du plafond par adresse sur un plafond global seul : sans lui,
// une machine affame tout le parc en occupant les places, et les postes
// légitimes sont refusés à sa place.
func TestPlafondParAdresse(t *testing.T) {
	l := NewLimiter("test", 100, 3)

	for i := 0; i < 3; i++ {
		if _, ok, _ := l.Acquire(conn("10.0.0.1")); !ok {
			t.Fatalf("connexion %d refusée alors que le plafond est 3", i+1)
		}
	}
	if _, ok, motif := l.Acquire(conn("10.0.0.1")); ok {
		t.Error("4ᵉ connexion acceptée alors que le plafond par adresse est 3")
	} else if motif == "" {
		t.Error("refus sans motif : le journal serait inexploitable")
	}

	// Une AUTRE adresse doit toujours passer : c'est tout l'objet.
	if _, ok, _ := l.Acquire(conn("10.0.0.2")); !ok {
		t.Error("une autre adresse est refusée : le plafond par adresse déborde")
	}
}

// TestPlafondGlobal : le total borne aussi la somme des usages normaux.
func TestPlafondGlobal(t *testing.T) {
	l := NewLimiter("test", 3, 10)

	for i := 0; i < 3; i++ {
		if _, ok, _ := l.Acquire(conn("10.0.0." + string(rune('1'+i)))); !ok {
			t.Fatalf("connexion %d refusée alors que le total est 3", i+1)
		}
	}
	if _, ok, _ := l.Acquire(conn("10.0.0.9")); ok {
		t.Error("4ᵉ connexion acceptée alors que le total est 3")
	}
}

// TestLibérationRendLaPlace.
func TestLibérationRendLaPlace(t *testing.T) {
	l := NewLimiter("test", 100, 1)

	release, ok, _ := l.Acquire(conn("10.0.0.1"))
	if !ok {
		t.Fatal("première connexion refusée")
	}
	if _, ok, _ := l.Acquire(conn("10.0.0.1")); ok {
		t.Fatal("deuxième acceptée alors que le plafond est 1")
	}

	release()
	if _, ok, _ := l.Acquire(conn("10.0.0.1")); !ok {
		t.Error("place non rendue après libération")
	}
}

// TestDoubleLibération : libérer deux fois ne doit pas rendre le plafond
// inopérant.
//
// Un defer mal placé produit exactement cela, sans bruit : le compteur passe
// sous zéro et le plafond ne se déclenche plus jamais.
func TestDoubleLibération(t *testing.T) {
	l := NewLimiter("test", 100, 2)

	release, _, _ := l.Acquire(conn("10.0.0.1"))
	release()
	release()
	release()

	total, _ := l.Stats()
	if total != 0 {
		t.Errorf("total = %d après libérations multiples, attendu 0", total)
	}

	// Le plafond doit encore fonctionner.
	l.Acquire(conn("10.0.0.1"))
	l.Acquire(conn("10.0.0.1"))
	if _, ok, _ := l.Acquire(conn("10.0.0.1")); ok {
		t.Error("plafond inopérant après une double libération")
	}
}

// TestTableNeGrossitPas : les adresses libérées quittent la table.
//
// Sans cela, la table gagne une entrée par adresse ayant tenté une connexion —
// ce qu'un balayage produit précisément en masse.
func TestTableNeGrossitPas(t *testing.T) {
	l := NewLimiter("test", 10000, 10)

	var libérations []func()
	for i := 0; i < 200; i++ {
		release, ok, _ := l.Acquire(conn("10.1." + string(rune('0'+i/100)) + "." + string(rune('0'+i%100))))
		if ok {
			libérations = append(libérations, release)
		}
	}
	for _, r := range libérations {
		r()
	}

	total, sources := l.Stats()
	if total != 0 || sources != 0 {
		t.Errorf("après libération : total=%d sources=%d, attendu 0 et 0", total, sources)
	}
}

// TestConcurrence : le compte reste exact sous accès simultanés.
//
// À lancer avec -race. Un compteur non protégé passe ce test sans -race et
// échoue avec : c'est précisément le genre de défaut qui ne se voit qu'en charge.
func TestConcurrence(t *testing.T) {
	l := NewLimiter("test", 1000, 1000)

	var wg sync.WaitGroup
	libérations := make(chan func(), 500)
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if release, ok, _ := l.Acquire(conn("10.0.0.1")); ok {
				libérations <- release
			}
		}()
	}
	wg.Wait()
	close(libérations)

	total, _ := l.Stats()
	if total != 500 {
		t.Errorf("total = %d après 500 acquisitions simultanées, attendu 500", total)
	}
	for r := range libérations {
		r()
	}
	if total, sources := l.Stats(); total != 0 || sources != 0 {
		t.Errorf("après libération : total=%d sources=%d", total, sources)
	}
}
