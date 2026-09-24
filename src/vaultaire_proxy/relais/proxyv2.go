package relais

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// En-tête PROXY protocol v2, placé devant une connexion LDAPS relayée
// (TO-DO 72).
//
// Il porte l'adresse du CLIENT, que le core ne verrait pas autrement : le
// relais recopie les octets sans les lire, et la connexion arrive de l'adresse
// du proxy. Sans lui, la limitation des échecs de bind compterait tout un site
// comme une seule source.
//
// Le core ne le croit que d'un proxy ENREGISTRÉ ; d'ailleurs, il ferme la
// connexion. Le format est celui de la spécification HAProxy : le lecteur
// (core/proxyproto) en a sa propre copie, les deux modules étant disjoints.

var signatureV2 = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// enteteV2 compose l'en-tête d'une connexion TCP : source = le client,
// destination = l'adresse où le proxy l'a reçue.
func enteteV2(src, dst net.Addr) ([]byte, error) {
	s, ok1 := src.(*net.TCPAddr)
	d, ok2 := dst.(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("adresses non TCP (%v → %v)", src, dst)
	}
	var b bytes.Buffer
	b.Write(signatureV2)
	s4, d4 := s.IP.To4(), d.IP.To4()
	switch {
	case s4 != nil && d4 != nil:
		b.Write([]byte{0x21, 0x11, 0, 12}) // v2 PROXY, TCP/IPv4, 12 octets
		b.Write(s4)
		b.Write(d4)
	case s4 == nil && d4 == nil:
		b.Write([]byte{0x21, 0x21, 0, 36}) // v2 PROXY, TCP/IPv6, 36 octets
		b.Write(s.IP.To16())
		b.Write(d.IP.To16())
	default:
		// Client IPv4 reçu sur une écoute IPv6 (« ::ffff:… » déjà ramené en
		// To4) et l'inverse : on exprime les deux en IPv6, forme commune.
		b.Write([]byte{0x21, 0x21, 0, 36})
		b.Write(s.IP.To16())
		b.Write(d.IP.To16())
	}
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], uint16(s.Port))
	binary.BigEndian.PutUint16(ports[2:4], uint16(d.Port))
	b.Write(ports[:])
	return b.Bytes(), nil
}
