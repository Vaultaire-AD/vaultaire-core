package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Structure de config
type Config struct {
	Server     string `json:"server"`
	Username   string `json:"username"`
	PrivateKey string `json:"private_key"`
}

// Structure de la requête/ réponse API
type CommandRequest struct {
	Command   string `json:"command"`
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type CommandResponse struct {
	Result string `json:"result"`
}

// Charge la config (~/.vaultaire/config.json)
func loadConfig() (Config, error) {
	usr, _ := user.Current()
	defaultPath := filepath.Join(usr.HomeDir, ".vaultaire", "config.json")
	path := defaultPath
	if os.Getenv("VAULTAIRE_CONFIG") != "" {
		path = os.Getenv("VAULTAIRE_CONFIG")
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("erreur lecture config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("erreur parse config: %w", err)
	}
	return cfg, nil
}

// Lecture clé privée RSA
func loadPrivateKey(path string) (ssh.Signer, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("lecture fichier impossible (%s): %v", path, err)
    }

    // Très important : Nettoie les espaces ou retours à la ligne en début/fin de fichier
    data = bytes.TrimSpace(data)

    signer, err := ssh.ParsePrivateKey(data)
    if err != nil {
        // %v affichera la raison réelle (ex: "ssh: no key found", "ssh: uncertified key", etc.)
        return nil, fmt.Errorf("raison technique: %v", err)
    }

    return signer, nil
}

// Signe un message avec RSA
func signMessage(signer ssh.Signer, message []byte) (string, error) {
	sig, err := signer.Sign(rand.Reader, message)
	if err != nil {
		return "", err
	}

	// encode TOUTE la signature SSH
	raw := ssh.Marshal(sig)

	return base64.StdEncoding.EncodeToString(raw), nil
}

// Génère un nonce : timestamp + 16 caractères aléatoires
func generateNonce() string {
	timestamp := time.Now().Unix()
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, 16)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	return fmt.Sprintf("%d-%s", timestamp, string(result))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: vaultairectl <commande>")
		os.Exit(1)
	}

	command := strings.Join(os.Args[1:], " ")
	// 1. Charger la config
	cfg, err := loadConfig()
	if err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}

	// 2. Charger clé privée
	priv, err := loadPrivateKey(cfg.PrivateKey)
	if err != nil {
		fmt.Println("❌ erreur clé privée:", err)
		os.Exit(1)
	}

	// 3. Générer nonce
	nonce := generateNonce()

	// 4. Préparer le body JSON sans signature pour le signer
	reqBodyToSign := struct {
		Command  string `json:"command"`
		Username string `json:"username"`
		Nonce    string `json:"nonce"`
	}{
		Command:  command,
		Username: cfg.Username,
		Nonce:    nonce,
	}
	bodyBytesToSign, _ := json.Marshal(reqBodyToSign)

	// 4. Signer le JSON
	sig, err := signMessage(priv, bodyBytesToSign)
	if err != nil {
		fmt.Println("❌ erreur signature:", err)
		os.Exit(1)
	}

	// 5. Préparer le body JSON final avec signature
	reqBody := CommandRequest{
		Command:   command,
		Username:  cfg.Username,
		Nonce:     nonce,
		Signature: sig,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	// 6. Envoyer la requête HTTP
	url := cfg.Server + "/api/command"
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ⚠️ en prod remplacer par vérif réelle
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("❌ erreur requête:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// 7. Lire la réponse
	respData, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		fmt.Println("❌ erreur serveur:", string(respData))
		os.Exit(1)
	}

	var result CommandResponse
	if err := json.Unmarshal(respData, &result); err != nil {
		fmt.Println("❌ réponse invalide:", string(respData))
		os.Exit(1)
	}

	fmt.Println("✅ Résultat:", result.Result)
}
