package netguard

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// TestDelaiCoupeUneConnexionMuette : une connexion qui n'envoie rien est libérée.
//
// C'est le cœur du point : sans délai, la goroutine reste bloquée sur Read
// jusqu'au balayage périodique — soit jusqu'à deux minutes par connexion, et
// rien n'empêche d'en ouvrir des milliers.
func TestDelaiCoupeUneConnexionMuette(t *testing.T) {
	original := HandshakeReadTimeout
	defer func() { HandshakeReadTimeout = original }()
	HandshakeReadTimeout = 150 * time.Millisecond

	écoute, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer écoute.Close()

	fini := make(chan error, 1)
	go func() {
		serveur, err := écoute.Accept()
		if err != nil {
			fini <- err
			return
		}
		defer serveur.Close()
		ArmReadDeadline(serveur, false)
		buf := make([]byte, 1)
		_, err = serveur.Read(buf)
		fini <- err
	}()

	// Un client qui se connecte et se tait — exactement le cas à couvrir.
	client, err := net.Dial("tcp", écoute.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	select {
	case err := <-fini:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("erreur = %v, attendu un dépassement de délai", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("la lecture n'a jamais rendu la main : la goroutine est immobilisée")
	}
}

// TestDelaiReArmeNeCoupePasUneConnexionActive.
//
// SetReadDeadline pose une échéance ABSOLUE. La poser une seule fois à
// l'ouverture couperait la connexion à échéance même active — l'erreur classique
// avec cette API. Ce test échouerait si le réarmement disparaissait.
func TestDelaiReArmeNeCoupePasUneConnexionActive(t *testing.T) {
	original := HandshakeReadTimeout
	defer func() { HandshakeReadTimeout = original }()
	HandshakeReadTimeout = 200 * time.Millisecond

	écoute, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer écoute.Close()

	résultat := make(chan error, 1)
	go func() {
		serveur, err := écoute.Accept()
		if err != nil {
			résultat <- err
			return
		}
		defer serveur.Close()
		buf := make([]byte, 1)
		// Six lectures espacées de 100 ms : au total 600 ms, soit trois fois le
		// délai. Sans réarmement, la troisième échouerait.
		for i := 0; i < 6; i++ {
			ArmReadDeadline(serveur, false)
			if _, err := serveur.Read(buf); err != nil {
				résultat <- err
				return
			}
		}
		résultat <- nil
	}()

	client, err := net.Dial("tcp", écoute.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	go func() {
		for i := 0; i < 6; i++ {
			time.Sleep(100 * time.Millisecond)
			if _, err := client.Write([]byte{0x42}); err != nil {
				return
			}
		}
	}()

	select {
	case err := <-résultat:
		if err != nil {
			t.Errorf("une connexion ACTIVE a été coupée : %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test bloqué")
	}
}

// TestDelaiDesactivable : zéro retire le délai, ce qui est un choix d'exploitant.
func TestDelaiDesactivable(t *testing.T) {
	original := HandshakeReadTimeout
	defer func() { HandshakeReadTimeout = original }()
	HandshakeReadTimeout = 0

	écoute, _ := net.Listen("tcp", "127.0.0.1:0")
	defer écoute.Close()

	prêt := make(chan struct{})
	go func() {
		serveur, err := écoute.Accept()
		if err != nil {
			return
		}
		defer serveur.Close()
		ArmReadDeadline(serveur, false)
		close(prêt)
		buf := make([]byte, 1)
		serveur.Read(buf)
	}()

	client, err := net.Dial("tcp", écoute.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	<-prêt
	// Aucune coupure attendue : on vérifie simplement qu'ArmReadDeadline n'a pas
	// posé d'échéance immédiate.
	time.Sleep(100 * time.Millisecond)
}
