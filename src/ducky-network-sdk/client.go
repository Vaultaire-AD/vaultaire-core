package duckynetwork

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type ClientOpts struct {
	CoreAddress     string
	ComputeurID     string
	PrivateKeyPEM   string
	ServerPubKeyPEM string
}

// Client gère auth, trames, parsing et extension de trames.
type Client struct {
	opts       ClientOpts
	conn       net.Conn
	sessionKey []byte
	isSafe     bool
	hostname   string
	registry   *Registry
	mu         sync.Mutex
}

func NewClient(opts ClientOpts) (*Client, error) {
	if opts.CoreAddress == "" || opts.ComputeurID == "" || opts.PrivateKeyPEM == "" || opts.ServerPubKeyPEM == "" {
		return nil, fmt.Errorf("core_address, computeur_id, private_key_pem et server_pub_key sont requis")
	}
	return &Client{opts: opts, registry: NewRegistry()}, nil
}

func (c *Client) RegisterParser(code string, parser ParserFunc) {
	c.registry.Register(code, parser)
}

func (c *Client) Connect() error {
	conn, err := net.DialTimeout("tcp", c.opts.CoreAddress, 10*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn

	hello := Frame{
		Code:     Trame01_01,
		Target:   "server_central",
		Session:  "",
		Username: "INIT",
		ClientID: c.opts.ComputeurID,
		Content:  "duckynetwork-auth",
	}
	if err := c.sendRawRSA(hello.Build()); err != nil {
		conn.Close()
		return fmt.Errorf("send 01_01: %w", err)
	}

	resp, err := c.readRawRSA()
	if err != nil {
		conn.Close()
		return fmt.Errorf("read 01_02: %w", err)
	}
	frame, err := ParseFrame(resp)
	if err != nil {
		conn.Close()
		return err
	}
	if frame.Code != Trame01_02 {
		conn.Close()
		return fmt.Errorf("expected 01_02, got %s", frame.Code)
	}
	c.sessionKey = normalizeSessionKey(frame.Session)
	c.isSafe = true
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *Client) LocalIP() string {
	if c.conn == nil {
		return ""
	}
	if tcp, ok := c.conn.LocalAddr().(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return ""
}

func (c *Client) Hostname() string { return c.hostname }
func (c *Client) SetHostname(v string) {
	c.hostname = v
}

func (c *Client) Send(frame Frame) (Frame, error) {
	frame.Session = c.sessionKeyString()
	if err := c.sendSecure(frame.Build()); err != nil {
		return Frame{}, err
	}
	resp, err := c.readSecure()
	if err != nil {
		return Frame{}, err
	}
	return ParseFrame(resp)
}

func (c *Client) RegisterHost(hostname, fqdn, ip, role, domain string) error {
	c.hostname = hostname
	content := strings.Join([]string{hostname, fqdn, ip, role, domain}, "\n")
	_, err := c.Send(Frame{
		Code:     Trame04_01,
		Target:   "server_central",
		Username: "host",
		ClientID: c.opts.ComputeurID,
		Content:  content,
	})
	return err
}

func (c *Client) ListCores() ([]CoreInfo, error) {
	resp, err := c.Send(Frame{
		Code:     Trame04_03,
		Target:   "server_central",
		Username: "host",
		ClientID: c.opts.ComputeurID,
		Content:  "",
	})
	if err != nil {
		return nil, err
	}
	parsed, err := c.registry.Parse(resp)
	if err != nil {
		return nil, err
	}
	cores, ok := parsed.([]CoreInfo)
	if !ok {
		return nil, fmt.Errorf("parser 04_04 returned unexpected type")
	}
	return cores, nil
}

func (c *Client) SendHeartbeat(hostname string) error {
	if hostname == "" {
		hostname = c.hostname
	}
	_, err := c.Send(Frame{
		Code:     Trame04_07,
		Target:   "server_central",
		Username: "host",
		ClientID: c.opts.ComputeurID,
		Content:  hostname,
	})
	return err
}

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
	dec, err := decryptRSA(c.opts.PrivateKeyPEM, data)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

func (c *Client) sendSecure(payload string) error {
	if !c.isSafe {
		return fmt.Errorf("secure session not established")
	}
	enc, err := encryptAESGCM(c.sessionKey, payload)
	if err != nil {
		return err
	}
	return writePacket(c.conn, []byte(enc))
}

func (c *Client) readSecure() (string, error) {
	if !c.isSafe {
		return "", fmt.Errorf("secure session not established")
	}
	data, err := readPacket(c.conn)
	if err != nil {
		return "", err
	}
	return decryptAESGCM(c.sessionKey, string(data))
}

func normalizeSessionKey(s string) []byte {
	key := []byte(s)
	if len(key) == 32 {
		return key
	}
	out := make([]byte, 32)
	copy(out, key)
	return out
}

func (c *Client) sessionKeyString() string {
	return string(c.sessionKey)
}
