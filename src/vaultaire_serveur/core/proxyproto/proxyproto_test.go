package proxyproto

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// L'en-tête PROXY v2 côté core.
//
// # Ce que ces tests gardent
//
//   - un client ORDINAIRE n'est pas gêné : ses octets arrivent intacts, sans
//     attente — y compris un message LDAP de sept octets, plus court que la
//     signature ;
//   - l'adresse d'origine n'est crue que d'un proxy enregistré, et un en-tête
//     venu d'ailleurs FERME la connexion : l'accepter donnerait à n'importe qui
//     le choix de l'adresse sous laquelle il est compté ;
//   - ce qui suit l'en-tête — la poignée de main TLS — n'est pas entamé.

// relier ouvre une connexion TCP locale, écrit `envoi` côté client et rend le
// côté serveur tel que l'écoute l'accepte.
func relier(t *testing.T, envoi []byte) (serveur net.Conn, client net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	client, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	serveur, err = l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serveur.Close() })
	if len(envoi) > 0 {
		if _, err := client.Write(envoi); err != nil {
			t.Fatal(err)
		}
	}
	return serveur, client
}

func toujours(string) bool { return true }
func jamais(string) bool   { return false }

func lireTout(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnClientOrdinairePasseIntact(t *testing.T) {
	// Un « unbind » LDAP : sept octets, moins que la signature.
	unbind := []byte{0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00}
	srv, _ := relier(t, unbind)

	debut := time.Now()
	c, err := Lire(srv, jamais, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(debut) > time.Second {
		t.Fatal("un message plus court que la signature a fait attendre : le " +
			"premier octet suffit à décider")
	}
	if got := lireTout(t, c, len(unbind)); string(got) != string(unbind) {
		t.Fatalf("octets reçus %x, envoyés %x", got, unbind)
	}
	if c.RemoteAddr().String() != srv.RemoteAddr().String() || c.Relais != nil {
		t.Fatalf("adresse %s (relais %v) : une connexion directe garde celle de son pair",
			c.RemoteAddr(), c.Relais)
	}
}

func TestLAdresseDOrigineVientDuProxy(t *testing.T) {
	origine := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51234}
	entete, err := Construire(origine, &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 636})
	if err != nil {
		t.Fatal(err)
	}
	helloTLS := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}
	srv, _ := relier(t, append(entete, helloTLS...))

	c, err := Lire(srv, toujours, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr().String() != origine.String() {
		t.Fatalf("adresse vue %s, attendu %s : la limitation des binds compterait "+
			"le proxy au lieu du client", c.RemoteAddr(), origine)
	}
	if c.Relais == nil || c.Relais.String() != srv.RemoteAddr().String() {
		t.Fatalf("relais = %v : le journal ne dirait pas par où le client est passé", c.Relais)
	}
	if got := lireTout(t, c, len(helloTLS)); string(got) != string(helloTLS) {
		t.Fatalf("poignée de main TLS entamée : %x", got)
	}
}

func TestUnEnteteVenuDAilleursEstRefuse(t *testing.T) {
	entete, _ := Construire(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1},
		&net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 636})
	srv, _ := relier(t, entete)

	_, err := Lire(srv, jamais, 2*time.Second)
	if !errors.Is(err, ErrNonDeConfiance) {
		t.Fatalf("err = %v : un pair quelconque choisirait l'adresse sous laquelle il est compté", err)
	}
}

func TestIPv6(t *testing.T) {
	origine := &net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 4000}
	entete, err := Construire(origine, &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 636})
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := relier(t, entete)
	c, err := Lire(srv, toujours, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr().String() != origine.String() {
		t.Fatalf("adresse vue %s, attendu %s", c.RemoteAddr(), origine)
	}
}

func TestLaCommandeLocalGardeLAdresseDuProxy(t *testing.T) {
	local := append(append([]byte(nil), signature...), 0x20, 0x00, 0x00, 0x00)
	srv, _ := relier(t, local)
	c, err := Lire(srv, toujours, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr().String() != srv.RemoteAddr().String() {
		t.Fatalf("LOCAL : adresse %s, attendu celle du proxy", c.RemoteAddr())
	}
}

func TestUnEnteteMalFormeEstRefuse(t *testing.T) {
	cas := map[string][]byte{
		"version 1":        append(append([]byte(nil), signature...), 0x11, famTCP4, 0, 12),
		"trop long":        append(append([]byte(nil), signature...), 0x21, famTCP4, 0xFF, 0xFF),
		"famille UDP":      append(append([]byte(nil), signature...), 0x21, 0x12, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
		"adresses courtes": append(append([]byte(nil), signature...), 0x21, famTCP4, 0, 4, 1, 2, 3, 4),
	}
	for nom, envoi := range cas {
		t.Run(nom, func(t *testing.T) {
			srv, _ := relier(t, envoi)
			if _, err := Lire(srv, toujours, time.Second); err == nil {
				t.Fatal("en-tête accepté : l'adresse d'origine serait devinée")
			}
		})
	}
}

func TestUnPairMuetNeTientPasSaPlace(t *testing.T) {
	srv, _ := relier(t, nil)
	debut := time.Now()
	if _, err := Lire(srv, toujours, 200*time.Millisecond); err == nil {
		t.Fatal("un pair muet a été accepté")
	}
	if time.Since(debut) > 2*time.Second {
		t.Fatal("le délai n'a pas borné l'attente du premier octet")
	}
}
