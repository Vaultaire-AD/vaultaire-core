package apiclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const commandEndpoint = "/api/command"

type Config struct {
	Server             string
	Username           string
	PrivateKeyPath     string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

type Client struct {
	server   string
	username string
	signer   ssh.Signer
	http     *http.Client
}

type commandRequest struct {
	Command  string `json:"command"`
	Username string `json:"username"`
	Nonce    string `json:"nonce"`
	// Timestamp entre dans le corps signé : le serveur refuse les requêtes hors
	// d'une fenêtre de deux minutes et mémorise les nonces vus pendant cette
	// fenêtre, ce qui rend une requête capturée inutilisable.
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type commandResponse struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Server) == "" {
		return nil, fmt.Errorf("server est requis")
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return nil, fmt.Errorf("username est requis")
	}
	if strings.TrimSpace(cfg.PrivateKeyPath) == "" {
		return nil, fmt.Errorf("private key path est requis")
	}

	privateKey, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("lecture cle privee impossible (%s): %w", cfg.PrivateKeyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(bytes.TrimSpace(privateKey))
	if err != nil {
		return nil, fmt.Errorf("cle privee invalide: %w", err)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		},
	}

	return &Client{
		server:   strings.TrimRight(cfg.Server, "/"),
		username: cfg.Username,
		signer:   signer,
		http:     httpClient,
	}, nil
}

func (c *Client) Execute(ctx context.Context, command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("commande vide")
	}

	nonce := generateNonce()
	// L'ordre des champs n'a pas d'importance (json.Marshal suit celui de la
	// structure), mais la structure DOIT rester identique à celle du serveur :
	// c'est l'octet à octet de ce JSON qui est signé puis revérifié.
	timestamp := time.Now().Unix()
	bodyToSign := struct {
		Command   string `json:"command"`
		Username  string `json:"username"`
		Nonce     string `json:"nonce"`
		Timestamp int64  `json:"timestamp"`
	}{
		Command:   command,
		Username:  c.username,
		Nonce:     nonce,
		Timestamp: timestamp,
	}

	bodyToSignRaw, err := json.Marshal(bodyToSign)
	if err != nil {
		return "", fmt.Errorf("build payload to sign: %w", err)
	}

	signatureB64, err := signMessage(c.signer, bodyToSignRaw)
	if err != nil {
		return "", fmt.Errorf("signature failed: %w", err)
	}

	reqPayload := commandRequest{
		Command:   command,
		Username:  c.username,
		Nonce:     nonce,
		Timestamp: timestamp,
		Signature: signatureB64,
	}
	payloadRaw, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("build request payload: %w", err)
	}

	url := c.server + commandEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(payloadRaw))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api status %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed commandResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("invalid response: %w", err)
	}
	if parsed.Error != "" {
		return "", errors.New(parsed.Error)
	}
	return parsed.Result, nil
}

func (c *Client) CreateUser(ctx context.Context, username, domain, password, birthdate string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("create -u %s %s %s %s", username, domain, password, birthdate))
}

func (c *Client) CreateUserWithNames(ctx context.Context, username, domain, password, birthdate, firstName, lastName string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("create -u %s %s %s %s %s %s", username, domain, password, birthdate, firstName, lastName))
}

func (c *Client) CreateGroup(ctx context.Context, groupName, domain string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("create -g %s %s", groupName, domain))
}

func (c *Client) AddUserToGroup(ctx context.Context, username, groupName string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("add -u %s -g %s", username, groupName))
}

func (c *Client) AddUserPermissionToGroup(ctx context.Context, groupName, permissionName string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("add -gu %s -p %s", groupName, permissionName))
}

func (c *Client) AddClientPermissionToGroup(ctx context.Context, groupName, permissionName string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("add -gc %s -p %s", groupName, permissionName))
}

func (c *Client) GetUsers(ctx context.Context) (string, error) {
	return c.Execute(ctx, "get -u")
}

func (c *Client) GetUser(ctx context.Context, username string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("get -u %s", username))
}

func (c *Client) GetUsersByGroup(ctx context.Context, groupName string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("get -u -g %s", groupName))
}

func (c *Client) GetGroups(ctx context.Context) (string, error) {
	return c.Execute(ctx, "get -g")
}

func (c *Client) GetGroup(ctx context.Context, groupName string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("get -g %s", groupName))
}

func (c *Client) GetGroupUsers(ctx context.Context, groupName string) (string, error) {
	return c.Execute(ctx, fmt.Sprintf("get -g -u %s", groupName))
}

func generateNonce() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, 16)
	for i := range token {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		token[i] = chars[n.Int64()]
	}
	return fmt.Sprintf("%d-%s", time.Now().Unix(), string(token))
}

func signMessage(signer ssh.Signer, message []byte) (string, error) {
	sig, err := signer.Sign(rand.Reader, message)
	if err != nil {
		return "", err
	}
	raw := ssh.Marshal(sig)
	return base64.StdEncoding.EncodeToString(raw), nil
}
