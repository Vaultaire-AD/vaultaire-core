// Package ldapclient est un client LDAP réduit à ce dont Nexus a besoin :
// ouvrir une session (bind simple) et lire des entrées (search).
//
// # Pourquoi pas go-ldap
//
// go-ldap tire golang.org/x/crypto pour des fonctions (NTLM, GSSAPI) que Nexus
// n'utilise pas. L'encodage BER vient de go-asn1-ber, la bibliothèque que le
// core utilise déjà pour son serveur LDAP : une seule implémentation BER dans
// le dépôt, des deux côtés du fil.
package ldapclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Codes de résultat utiles.
const (
	ResultSuccess            = 0
	ResultNoSuchObject       = 32
	ResultInvalidCredentials = 49
	ResultInsufficientAccess = 50
)

const (
	appBindRequest       = 0
	appBindResponse      = 1
	appUnbindRequest     = 2
	appSearchRequest     = 3
	appSearchResultEntry = 4
	appSearchResultDone  = 5
	appSearchResultRef   = 19
)

// Error porte le code de résultat LDAP.
type Error struct {
	Code    int64
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("LDAP %d : %s", e.Code, e.Message)
	}
	return fmt.Sprintf("LDAP %d", e.Code)
}

// IsCode dit si err est une erreur LDAP de ce code.
func IsCode(err error, code int64) bool {
	var le *Error
	return errors.As(err, &le) && le.Code == code
}

// Options de connexion.
type Options struct {
	URL                string
	CAFile             string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// Conn est une connexion LDAP. Les requêtes sont séquentielles.
type Conn struct {
	mu      sync.Mutex
	conn    net.Conn
	msgID   int64
	timeout time.Duration
}

// Dial ouvre une connexion ldap:// ou ldaps://.
func Dial(o Options) (*Conn, error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return nil, fmt.Errorf("URL LDAP invalide : %w", err)
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	host := u.Host
	d := &net.Dialer{Timeout: o.Timeout}
	var c net.Conn
	switch u.Scheme {
	case "ldap":
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "389")
		}
		c, err = d.Dial("tcp", host)
	case "ldaps":
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "636")
		}
		cfg := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureSkipVerify}
		if o.CAFile != "" {
			pem, rerr := os.ReadFile(o.CAFile)
			if rerr != nil {
				return nil, fmt.Errorf("ca_file : %w", rerr)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("ca_file : aucun certificat lisible")
			}
			cfg.RootCAs = pool
		}
		c, err = tls.DialWithDialer(d, "tcp", host, cfg)
	default:
		return nil, fmt.Errorf("schéma LDAP %q non pris en charge (ldap, ldaps)", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	return &Conn{conn: c, timeout: o.Timeout}, nil
}

// Close envoie un unbind et ferme.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgID++
	p := envelope(c.msgID)
	p.AppendChild(ber.Encode(ber.ClassApplication, ber.TypePrimitive, appUnbindRequest, nil, "Unbind"))
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = c.conn.Write(p.Bytes())
	return c.conn.Close()
}

func envelope(id int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	return p
}

func (c *Conn) send(op *ber.Packet) (int64, error) {
	c.msgID++
	p := envelope(c.msgID)
	p.AppendChild(op)
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))
	_, err := c.conn.Write(p.Bytes())
	return c.msgID, err
}

func (c *Conn) read(id int64) (*ber.Packet, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	p, err := ber.ReadPacket(c.conn)
	if err != nil {
		return nil, err
	}
	if len(p.Children) < 2 {
		return nil, errors.New("réponse LDAP malformée")
	}
	if got, ok := p.Children[0].Value.(int64); !ok || got != id {
		return nil, errors.New("réponse LDAP inattendue (identifiant de message)")
	}
	return p.Children[1], nil
}

func result(op *ber.Packet) error {
	if len(op.Children) < 3 {
		return errors.New("résultat LDAP malformé")
	}
	code, _ := op.Children[0].Value.(int64)
	if code == ResultSuccess {
		return nil
	}
	msg, _ := op.Children[2].Value.(string)
	return &Error{Code: code, Message: msg}
}

// Bind ouvre une session simple. Un mot de passe vide est refusé ici : en
// LDAP, c'est un bind ANONYME qui réussit — le piège classique qui fait
// accepter n'importe quel compte sans mot de passe.
func (c *Conn) Bind(dn, password string) error {
	if password == "" {
		return &Error{Code: ResultInvalidCredentials, Message: "mot de passe vide refusé"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appBindRequest, nil, "Bind Request")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "Version"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "DN"))
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, password, "Password"))
	id, err := c.send(op)
	if err != nil {
		return err
	}
	resp, err := c.read(id)
	if err != nil {
		return err
	}
	if resp.Tag != appBindResponse {
		return errors.New("réponse de bind inattendue")
	}
	return result(resp)
}

// Entry est une entrée lue.
type Entry struct {
	DN    string
	Attrs map[string][]string // clés en minuscules
}

// Get rend la première valeur d'un attribut.
func (e Entry) Get(attr string) string {
	v := e.Attrs[strings.ToLower(attr)]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// Search lit les entrées sous base (sous-arbre) qui satisfont filter.
func (c *Conn) Search(base, filter string, attrs []string, sizeLimit int) ([]Entry, error) {
	f, err := CompileFilter(filter)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchRequest, nil, "Search Request")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, base, "Base"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(2), "Scope: subtree"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "Deref"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(sizeLimit), "Size"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.timeout/time.Second), "Time"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "TypesOnly"))
	op.AppendChild(f)
	al := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, a := range attrs {
		al.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "Attr"))
	}
	op.AppendChild(al)
	id, err := c.send(op)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for {
		resp, err := c.read(id)
		if err != nil {
			return nil, err
		}
		switch resp.Tag {
		case appSearchResultEntry:
			if len(resp.Children) < 2 {
				continue
			}
			e := Entry{Attrs: map[string][]string{}}
			e.DN, _ = resp.Children[0].Value.(string)
			for _, a := range resp.Children[1].Children {
				if len(a.Children) < 2 {
					continue
				}
				name, _ := a.Children[0].Value.(string)
				name = strings.ToLower(name)
				for _, v := range a.Children[1].Children {
					s, ok := v.Value.(string)
					if !ok {
						s = string(v.Data.Bytes())
					}
					e.Attrs[name] = append(e.Attrs[name], s)
				}
			}
			out = append(out, e)
		case appSearchResultRef:
			// référence : ignorée
		case appSearchResultDone:
			if err := result(resp); err != nil {
				return out, err
			}
			return out, nil
		default:
			return nil, fmt.Errorf("réponse de recherche inattendue (%d)", resp.Tag)
		}
	}
}

// EscapeFilter échappe une valeur à insérer dans un filtre (RFC 4515).
// Sans lui, un identifiant « *) (uid=* » élargirait la recherche.
func EscapeFilter(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '*', '(', ')', '\\', 0:
			fmt.Fprintf(&b, "\\%02x", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// EscapeDN échappe une valeur d'attribut dans un DN (RFC 4514).
func EscapeDN(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case strings.IndexByte(",+\"\\<>;=", c) >= 0,
			i == 0 && (c == ' ' || c == '#'),
			i == len(s)-1 && c == ' ':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
