package ducky

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	Trame01_01 = "01_01"
	Trame01_02 = "01_02"
	Trame04_01 = "04_01"
	Trame04_02 = "04_02"
	Trame04_03 = "04_03"
	Trame04_04 = "04_04"
	Trame04_07 = "04_07"
	Trame04_08 = "04_08"
)

type ClientOpts struct {
	CoreAddress     string
	ComputeurID     string
	PrivateKeyPEM   string
	ServerPubKeyPEM string
}

type Client struct {
	opts       ClientOpts
	conn       net.Conn
	sessionKey []byte // 32 bytes for AES-GCM after 01_02
	isSafe     bool
	hostname   string
	mu         sync.Mutex
}

func NewClient(opts ClientOpts) (*Client, error) {
	if opts.ComputeurID == "" || opts.PrivateKeyPEM == "" || opts.ServerPubKeyPEM == "" {
		return nil, fmt.Errorf("computeur_id, private_key_pem et server_pub_key requis")
	}
	return &Client{opts: opts}, nil
}

func (c *Client) Connect() error {
	conn, err := net.DialTimeout("tcp", c.opts.CoreAddress, 10*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn

	// 01_01 : client ask server auth (proof of work)
	randomData := make([]byte, 16)
	for i := range randomData {
		randomData[i] = byte(i + 1)
	}
	msg := fmt.Sprintf("%s\nserver_central\n\nINIT\n%s\n%s", Trame01_01, c.opts.ComputeurID, string(randomData))
	encrypted, err := encryptRSA(c.opts.ServerPubKeyPEM, msg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("encrypt 01_01: %w", err)
	}
	if err := c.writeFrame(encrypted); err != nil {
		conn.Close()
		return err
	}

	// Lire 01_02 (server proof of work) : réponse chiffrée avec notre clé publique
	decrypted, err := c.readFrameRSA()
	if err != nil {
		conn.Close()
		return fmt.Errorf("read 01_02: %w", err)
	}
	lines := strings.Split(decrypted, "\n")
	if len(lines) < 3 || lines[0] != Trame01_02 {
		conn.Close()
		return fmt.Errorf("réponse attendue 01_02, reçu: %s", decrypted)
	}
	sessionKeyStr := strings.TrimSpace(lines[2])
	c.sessionKey = []byte(sessionKeyStr)
	if len(c.sessionKey) != 32 {
		// padding ou troncature pour avoir 32 bytes
		if len(c.sessionKey) < 32 {
			padded := make([]byte, 32)
			copy(padded, c.sessionKey)
			c.sessionKey = padded
		} else {
			c.sessionKey = c.sessionKey[:32]
		}
	}
	c.isSafe = true
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *Client) LocalIP() string {
	if c.conn == nil {
		return ""
	}
	addr := c.conn.LocalAddr()
	if t, ok := addr.(*net.TCPAddr); ok {
		return t.IP.String()
	}
	return ""
}

func (c *Client) Hostname() string     { return c.hostname }
func (c *Client) SetHostname(h string) { c.hostname = h }

func (c *Client) writeFrame(payload []byte) error {
	sizeBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBuf, uint16(len(payload)))
	headerSize := byte(len(sizeBuf))
	data := append([]byte{headerSize}, sizeBuf...)
	data = append(data, payload...)
	_, err := c.conn.Write(data)
	return err
}

func (c *Client) readFrameRSA() (string, error) {
	headerSizeBuf := make([]byte, 1)
	if _, err := c.conn.Read(headerSizeBuf); err != nil {
		return "", err
	}
	sizeBuf := make([]byte, int(headerSizeBuf[0]))
	if _, err := c.conn.Read(sizeBuf); err != nil {
		return "", err
	}
	var msgLen uint16
	if len(sizeBuf) == 2 {
		msgLen = binary.BigEndian.Uint16(sizeBuf)
	} else {
		msgLen = uint16(sizeBuf[0])<<8 | uint16(sizeBuf[1])
	}
	payload := make([]byte, msgLen)
	if _, err := c.conn.Read(payload); err != nil {
		return "", err
	}
	dec, err := decryptRSA(c.opts.PrivateKeyPEM, payload)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

func (c *Client) readFrameAES() (string, error) {
	headerSizeBuf := make([]byte, 1)
	if _, err := c.conn.Read(headerSizeBuf); err != nil {
		return "", err
	}
	sizeBuf := make([]byte, int(headerSizeBuf[0]))
	if _, err := c.conn.Read(sizeBuf); err != nil {
		return "", err
	}
	var msgLen uint16
	if len(sizeBuf) == 2 {
		msgLen = binary.BigEndian.Uint16(sizeBuf)
	} else {
		msgLen = uint16(sizeBuf[0])<<8 | uint16(sizeBuf[1])
	}
	payload := make([]byte, msgLen)
	if _, err := c.conn.Read(payload); err != nil {
		return "", err
	}
	return decryptAESGCM(c.sessionKey, string(payload))
}

func (c *Client) sendSecure(msg string) error {
	enc, err := encryptAESGCM(c.sessionKey, msg)
	if err != nil {
		return err
	}
	return c.writeFrame([]byte(enc))
}

// RegisterHost envoie 04_01 (register_host). Content: hostname\nfqdn\nip\nrole\ndomain
func (c *Client) RegisterHost(hostname, fqdn, ip, role, domain string) error {
	c.hostname = hostname
	content := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", hostname, fqdn, ip, role, domain)
	// Format attendu par le serveur: 04_01\nserver_central\nsessionKey\nusername\nclientID\ncontent
	msg := fmt.Sprintf("%s\nserver_central\n%s\nhost\n%s\n%s", Trame04_01, c.sessionKeyStr(), c.opts.ComputeurID, content)
	if err := c.sendSecure(msg); err != nil {
		return err
	}
	resp, err := c.readFrameAES()
	if err != nil {
		return err
	}
	lines := strings.Split(resp, "\n")
	if len(lines) > 0 && lines[0] != Trame04_02 {
		return fmt.Errorf("réponse attendue 04_02, reçu: %s", lines[0])
	}
	return nil
}

func (c *Client) sessionKeyStr() string {
	if len(c.sessionKey) == 0 {
		return ""
	}
	return string(c.sessionKey)
}

// ListCores envoie 04_03 et retourne la liste des Cores (hostname|ip|version|capabilities).
func (c *Client) ListCores() ([]CoreInfo, error) {
	msg := fmt.Sprintf("%s\nserver_central\n%s\nhost\n%s\n", Trame04_03, c.sessionKeyStr(), c.opts.ComputeurID)
	if err := c.sendSecure(msg); err != nil {
		return nil, err
	}
	resp, err := c.readFrameAES()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(resp, "\n")
	if len(lines) == 0 || lines[0] != Trame04_04 {
		return nil, fmt.Errorf("réponse attendue 04_04, reçu: %s", resp)
	}
	// Format: 04_04\nserver_central\nsk\nun\ncid\ncount\nline1\nline2 (each line: hostname|ip|version|capabilities)
	var count int
	start := 6
	if len(lines) > 5 {
		fmt.Sscanf(lines[5], "%d", &count)
	}
	var out []CoreInfo
	for i := start; i < len(lines) && len(out) < count; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 2 {
			info := CoreInfo{Hostname: parts[0], IP: parts[1]}
			if len(parts) >= 3 {
				info.Version = parts[2]
			}
			if len(parts) >= 4 {
				info.Capabilities = parts[3]
			}
			out = append(out, info)
		}
	}
	return out, nil
}

// SendHeartbeat envoie 04_07 (host_heartbeat). Content: hostname
func (c *Client) SendHeartbeat(hostname string) error {
	if hostname == "" {
		hostname = c.hostname
	}
	msg := fmt.Sprintf("%s\nserver_central\n%s\nhost\n%s\n%s", Trame04_07, c.sessionKeyStr(), c.opts.ComputeurID, hostname)
	if err := c.sendSecure(msg); err != nil {
		return err
	}
	resp, err := c.readFrameAES()
	if err != nil {
		return err
	}
	lines := strings.Split(resp, "\n")
	if len(lines) > 0 && lines[0] != Trame04_08 {
		return fmt.Errorf("réponse attendue 04_08, reçu: %s", lines[0])
	}
	return nil
}

type CoreInfo struct {
	Hostname     string
	IP           string
	Version      string
	Capabilities string
}
