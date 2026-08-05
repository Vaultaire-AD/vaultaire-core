package duckynetwork

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Client est la connexion d'un programme au core.
//
// # Ce que le SDK prend en charge pour tout le monde
//
// Les catégories 01 et 02 sont communes à TOUS les clients : poignée de main,
// enrôlement, authentification, fermeture de session. Elles sont traitées ici, et
// aucun consommateur n'a à les réimplémenter — c'est précisément ce qui garantit
// qu'un durcissement du protocole profite à tous les programmes d'un coup.
//
// Tout le reste est DÉLÉGUÉ : les GPO d'un agent, le cluster d'un proxy, les
// commandes d'une interface web. Le SDK ne sait pas ce que ces trames veulent
// dire et n'a pas à le savoir. Voir splitter.go.
type Client struct {
	opts     ClientOpts
	conn     net.Conn
	sessKey  []byte
	isSafe   bool
	hostname string
	registry *Registry
	splitter *Splitter
	mu       sync.Mutex
}

// ClientOpts décrit ce qu'il faut pour se connecter.
type ClientOpts struct {
	CoreAddress     string
	ComputeurID     string
	PrivateKeyPEM   string
	ServerPubKeyPEM string

	// Username est l'identité annoncée dans les trames montantes. Les agents
	// utilisent « vaultaire » ; un service peut porter son propre nom.
	Username string
}

// NewClient prépare un client sans se connecter.
func NewClient(opts ClientOpts) (*Client, error) {
	missing := []string{}
	if opts.CoreAddress == "" {
		missing = append(missing, "core_address")
	}
	if opts.ComputeurID == "" {
		missing = append(missing, "computeur_id")
	}
	if opts.PrivateKeyPEM == "" {
		missing = append(missing, "private_key_pem")
	}
	if opts.ServerPubKeyPEM == "" {
		missing = append(missing, "server_pub_key")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("configuration incomplète : %s", strings.Join(missing, ", "))
	}
	if opts.Username == "" {
		opts.Username = "vaultaire"
	}
	return &Client{opts: opts, registry: NewRegistry(), splitter: NewSplitter()}, nil
}

// RegisterParser branche un analyseur de réponse.
func (c *Client) RegisterParser(code string, parser ParserFunc) { c.registry.Register(code, parser) }

// Handle branche un gestionnaire pour une catégorie de trames.
//
// Voir Splitter : 01 et 02 ne sont pas délégables, le SDK les traite lui-même.
func (c *Client) Handle(category string, h CategoryHandler) error {
	return c.splitter.Handle(category, h)
}

// dialCore ouvre une connexion TCP vers le core.
func dialCore(address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connexion à %s : %w", address, err)
	}
	return conn, nil
}

// Connect exécute la poignée de main 01_01 / 01_02.
//
// # Ce que la réponse prouve
//
// Le core chiffre 01_02 avec la clé publique de l'identifiant annoncé. La
// déchiffrer prouve donc que nous détenons la privée correspondante — et à
// l'inverse, un échec de déchiffrement signifie que le core ne nous reconnaît
// plus sous cet identifiant. C'est ce que ErrIdentityRejected fait remonter, et
// c'est ce qui déclenche l'auto-réinitialisation.
func (c *Client) Connect() error {
	conn, err := dialCore(c.opts.CoreAddress)
	if err != nil {
		return err
	}
	c.conn = conn

	hello := Frame{
		Code:     Trame01_01,
		Target:   TargetCore,
		Session:  "",
		Username: "INIT",
		ClientID: c.opts.ComputeurID,
		Content:  "duckynetwork-auth",
	}
	if err := c.sendRawRSA(hello.Build()); err != nil {
		c.closeConn()
		return fmt.Errorf("envoi de 01_01 : %w", err)
	}

	resp, err := c.readRawRSA()
	if err != nil {
		c.closeConn()
		// Le core a répondu, mais nous ne savons pas lire sa réponse : elle est
		// chiffrée pour une clé qui n'est pas la nôtre. Notre identité n'est
		// plus reconnue.
		return fmt.Errorf("%w: %v", ErrIdentityRejected, err)
	}
	frame, err := ParseFrame(resp)
	if err != nil {
		c.closeConn()
		return err
	}
	if frame.Code != Trame01_02 {
		c.closeConn()
		return fmt.Errorf("réponse inattendue à la poignée de main : %s", frame.Code)
	}

	c.sessKey = normalizeSessionKey(frame.Session)
	c.isSafe = true
	return nil
}

// Close ferme la connexion.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeConnLocked()
}

func (c *Client) closeConn() {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.closeConnLocked()
}

func (c *Client) closeConnLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	c.isSafe = false
	return err
}

// Connected indique si la session chiffrée est établie.
func (c *Client) Connected() bool { return c.isSafe && c.conn != nil }

// ComputeurID retourne l'identifiant machine de ce client.
func (c *Client) ComputeurID() string { return c.opts.ComputeurID }

// LocalIP retourne l'adresse locale de la connexion, pour se déclarer au cluster.
func (c *Client) LocalIP() string {
	if c.conn == nil {
		return ""
	}
	if tcp, ok := c.conn.LocalAddr().(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return ""
}

func (c *Client) Hostname() string     { return c.hostname }
func (c *Client) SetHostname(v string) { c.hostname = v }

// Send envoie une trame et attend la réponse.
//
// L'envoi et la lecture sont sérialisés par le mutex : le protocole est en
// question/réponse sur une seule connexion, deux appels concurrents
// intervertiraient les réponses.
func (c *Client) Send(frame Frame) (Frame, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	frame.Session = string(c.sessKey)
	if frame.Target == "" {
		frame.Target = TargetCore
	}
	if frame.Username == "" {
		frame.Username = c.opts.Username
	}
	if frame.ClientID == "" {
		frame.ClientID = c.opts.ComputeurID
	}
	if err := c.sendSecure(frame.Build()); err != nil {
		return Frame{}, err
	}
	resp, err := c.readSecure()
	if err != nil {
		return Frame{}, err
	}
	return ParseFrame(resp)
}

// Dispatch remet une trame reçue au splitter.
func (c *Client) Dispatch(frame Frame) error { return c.splitter.Dispatch(c, frame) }

func (c *Client) sendRawRSA(payload string) error {
	enc, err := encryptRSA(c.opts.ServerPubKeyPEM, payload)
	if err != nil {
		return err
	}
	return writePacket(c.conn, enc)
}

func (c *Client) readRawRSA() (string, error) {
	data, err := readPacket(c.conn)
	if err != nil {
		return "", err
	}
	return decryptRSA(c.opts.PrivateKeyPEM, data)
}

func (c *Client) sendSecure(payload string) error {
	if !c.isSafe {
		return fmt.Errorf("session chiffrée non établie")
	}
	enc, err := encryptAESGCM(c.sessKey, payload)
	if err != nil {
		return err
	}
	return writePacket(c.conn, []byte(enc))
}

func (c *Client) readSecure() (string, error) {
	if !c.isSafe {
		return "", fmt.Errorf("session chiffrée non établie")
	}
	data, err := readPacket(c.conn)
	if err != nil {
		return "", err
	}
	return decryptAESGCM(c.sessKey, string(data))
}

// normalizeSessionKey ramène la clé de session à 32 octets.
//
// Le core la génère sur 32 octets ; le complément à zéro n'est là que pour ne pas
// paniquer si une version antérieure en envoyait une plus courte.
func normalizeSessionKey(s string) []byte {
	key := []byte(s)
	if len(key) == 32 {
		return key
	}
	out := make([]byte, 32)
	copy(out, key)
	return out
}
