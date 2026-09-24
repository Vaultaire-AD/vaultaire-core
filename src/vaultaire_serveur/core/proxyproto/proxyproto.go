// Package proxyproto lit l'en-tête PROXY protocol v2 qu'un proxy du cluster
// place devant une connexion relayée (TO-DO 72).
//
// # Le problème
//
// Le relais d'un proxy recopie les octets sans les lire : le core voit arriver
// la connexion depuis l'adresse DU PROXY. Pour LDAP, c'est grave : la
// limitation des échecs de bind compte par adresse source, et tout un site
// partagerait un seul compteur. Un poste qui se trompe de mot de passe en
// boucle ferait freiner tout le site ; un balayage d'un mot de passe sur mille
// comptes ne serait freiné par rien d'autre que le compteur par compte.
//
// L'en-tête PROXY v2 (HAProxy, 2017) transmet l'adresse d'origine devant les
// octets du client, avant même la poignée de main TLS : le relais n'a pas à
// terminer TLS pour la connaître.
//
// # La règle qui rend l'en-tête sûr
//
// Il n'est CRU que si le pair TCP est un proxy enregistré. Sinon, n'importe
// qui choisirait l'adresse sous laquelle il se présente — un compteur neuf à
// chaque tentative, ou l'adresse d'un collègue à faire pénaliser. Un en-tête
// venant d'ailleurs n'est pas ignoré : il est REFUSÉ, la connexion fermée.
// Quelqu'un qui en envoie un sans être un proxy essaie précisément cela.
//
// Un proxy peut aussi se connecter SANS en-tête (ses propres requêtes) : la
// connexion est alors traitée normalement, sous l'adresse du proxy.
//
// # Pourquoi aucun client ordinaire n'est gêné
//
// L'en-tête commence par \r (0x0D). Un message LDAP commence par 0x30 (une
// SEQUENCE BER), une poignée de main TLS par 0x16. Un seul octet suffit donc à
// décider, sans attendre qu'un client ait envoyé douze octets qu'il n'enverra
// peut-être jamais — un « unbind » LDAP en fait sept.
package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// signature ouvre tout en-tête PROXY v2.
var signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// Commandes et familles.
const (
	cmdLocal = 0x0
	cmdProxy = 0x1

	famTCP4 = 0x11
	famTCP6 = 0x21
)

// longueurMax borne la partie variable. Adresses IPv6 (36 octets) plus des TLV
// que nous n'employons pas : 512 laisse de la marge sans laisser un pair
// réserver de la mémoire à sa guise.
const longueurMax = 512

// ErrNonDeConfiance : un en-tête PROXY envoyé par un pair qui n'est pas un
// proxy enregistré.
var ErrNonDeConfiance = errors.New("en-tête PROXY reçu d'un pair qui n'est pas un proxy enregistré")

// Conn est une connexion dont l'adresse distante peut venir d'un en-tête.
type Conn struct {
	net.Conn
	lecteur  *bufio.Reader
	distante net.Addr

	// Relais est l'adresse du proxy qui a relayé, nil pour une connexion
	// directe. Le journal la cite : une ligne qui ne nommerait que le client
	// cacherait par où il est passé.
	Relais net.Addr
}

// Read lit à travers le tampon qui a servi à examiner le premier octet.
func (c *Conn) Read(p []byte) (int, error) { return c.lecteur.Read(p) }

// RemoteAddr rend l'adresse d'ORIGINE pour une connexion relayée.
//
// C'est le point qui fait tout tenir : la limitation des binds, les journaux
// et la session LDAP lisent tous RemoteAddr, et reçoivent donc l'adresse du
// client sans qu'aucun d'eux n'ait à connaître l'existence du relais.
func (c *Conn) RemoteAddr() net.Addr {
	if c.distante != nil {
		return c.distante
	}
	return c.Conn.RemoteAddr()
}

// Lire examine le début d'une connexion acceptée.
//
// Rend une connexion à employer À LA PLACE de celle reçue — le premier octet
// a été lu dans un tampon qu'elle seule détient.
//
// `delai` borne l'attente du premier octet et de l'en-tête : sans lui, un pair
// muet tiendrait une place jusqu'au délai de la session.
func Lire(conn net.Conn, deConfiance func(ip string) bool, delai time.Duration) (*Conn, error) {
	c := &Conn{Conn: conn, lecteur: bufio.NewReader(conn)}

	if delai > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(delai))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}

	premier, err := c.lecteur.Peek(1)
	if err != nil {
		return nil, err
	}
	if premier[0] != signature[0] {
		return c, nil
	}
	debut, err := c.lecteur.Peek(len(signature))
	if err != nil || !bytes.Equal(debut, signature) {
		// Commence par \r sans être un en-tête : ce n'est ni LDAP ni TLS, mais
		// ce n'est pas à ce paquet d'en juger. Le protocole refusera.
		return c, nil
	}

	pair := ipDe(conn.RemoteAddr())
	if deConfiance == nil || !deConfiance(pair) {
		return nil, fmt.Errorf("%w (%s)", ErrNonDeConfiance, pair)
	}

	src, err := lireEntete(c.lecteur)
	if err != nil {
		return nil, fmt.Errorf("en-tête PROXY de %s illisible : %w", pair, err)
	}
	if src != nil {
		c.distante = src
		c.Relais = conn.RemoteAddr()
	}
	return c, nil
}

// lireEntete consomme un en-tête v2 et rend l'adresse source. Nil pour une
// commande LOCAL (contrôle de santé du proxy) : la connexion garde alors
// l'adresse du proxy, ce qu'elle est.
func lireEntete(r *bufio.Reader) (net.Addr, error) {
	if _, err := r.Discard(len(signature)); err != nil {
		return nil, err
	}
	var fixe [4]byte
	if _, err := io.ReadFull(r, fixe[:]); err != nil {
		return nil, err
	}
	if fixe[0]>>4 != 2 {
		return nil, fmt.Errorf("version %d, seule la v2 est lue", fixe[0]>>4)
	}
	cmd, fam := fixe[0]&0x0F, fixe[1]
	longueur := int(binary.BigEndian.Uint16(fixe[2:]))
	if longueur > longueurMax {
		return nil, fmt.Errorf("partie variable de %d octets, au-delà de %d", longueur, longueurMax)
	}
	reste := make([]byte, longueur)
	if _, err := io.ReadFull(r, reste); err != nil {
		return nil, err
	}

	switch cmd {
	case cmdLocal:
		return nil, nil
	case cmdProxy:
	default:
		return nil, fmt.Errorf("commande %d inconnue", cmd)
	}

	switch fam {
	case famTCP4:
		if len(reste) < 12 {
			return nil, fmt.Errorf("adresses TCP/IPv4 tronquées")
		}
		return &net.TCPAddr{IP: net.IP(append([]byte(nil), reste[0:4]...)),
			Port: int(binary.BigEndian.Uint16(reste[8:10]))}, nil
	case famTCP6:
		if len(reste) < 36 {
			return nil, fmt.Errorf("adresses TCP/IPv6 tronquées")
		}
		return &net.TCPAddr{IP: net.IP(append([]byte(nil), reste[0:16]...)),
			Port: int(binary.BigEndian.Uint16(reste[32:34]))}, nil
	default:
		// Un proxy Vaultaire ne relaie que du TCP. Une autre famille est une
		// faute du pair, et deviner une adresse serait pire que refuser.
		return nil, fmt.Errorf("famille 0x%02x non gérée", fam)
	}
}

// Construire compose un en-tête v2 PROXY pour une connexion TCP.
//
// Côté core, il ne sert qu'aux tests. Le proxy a sa propre copie : les deux
// modules sont disjoints, et le format est figé par la spécification, pas par
// l'un d'eux.
func Construire(src, dst *net.TCPAddr) ([]byte, error) {
	var b bytes.Buffer
	b.Write(signature)
	s4, d4 := src.IP.To4(), dst.IP.To4()
	switch {
	case s4 != nil && d4 != nil:
		b.Write([]byte{0x20 | cmdProxy, famTCP4, 0, 12})
		b.Write(s4)
		b.Write(d4)
	case s4 == nil && d4 == nil && src.IP.To16() != nil && dst.IP.To16() != nil:
		b.Write([]byte{0x20 | cmdProxy, famTCP6, 0, 36})
		b.Write(src.IP.To16())
		b.Write(dst.IP.To16())
	default:
		return nil, fmt.Errorf("familles d'adresses différentes : %s → %s", src, dst)
	}
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], uint16(src.Port))
	binary.BigEndian.PutUint16(ports[2:4], uint16(dst.Port))
	b.Write(ports[:])
	return b.Bytes(), nil
}

func ipDe(a net.Addr) string {
	if a == nil {
		return ""
	}
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP.String()
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}
