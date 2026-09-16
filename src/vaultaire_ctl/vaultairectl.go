package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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

	// CACertificate : le certificat de l'autorité qui a signé celui du core.
	//
	// Vide, on s'en remet au magasin de confiance du système. Renseigné, il
	// s'ajoute — le core utilisant par défaut un certificat auto-signé, c'est
	// le chemin normal.
	CACertificate string `json:"ca_certificate,omitempty"`

	// InsecureSkipVerify désactive toute vérification du certificat.
	//
	// À réserver au diagnostic. Cet outil parle à l'API d'administration :
	// c'est le canal par lequel passent les gestes les plus lourds du système,
	// et n'importe qui sur le chemin réseau peut s'y substituer si le
	// certificat n'est pas vérifié.
	//
	// Faux par défaut, et c'est le changement : la valeur était codée en dur à
	// vrai, avec un commentaire « en prod remplacer par vérif réelle » qui
	// n'avait jamais été suivi.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// Structure de la requête/ réponse API
type CommandRequest struct {
	Command  string `json:"command"`
	Username string `json:"username"`
	Nonce    string `json:"nonce"`
	// Timestamp entre dans le corps signé. Le serveur refuse au-delà de deux
	// minutes d'écart et mémorise les nonces de la fenêtre courante : une
	// requête capturée sur le réseau n'est plus rejouable.
	Timestamp int64  `json:"timestamp"`
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
	// Structure strictement identique à celle du serveur : c'est ce JSON exact
	// qui est signé puis revérifié octet à octet.
	timestamp := time.Now().Unix()
	reqBodyToSign := struct {
		Command   string `json:"command"`
		Username  string `json:"username"`
		Nonce     string `json:"nonce"`
		Timestamp int64  `json:"timestamp"`
	}{
		Command:   command,
		Username:  cfg.Username,
		Nonce:     nonce,
		Timestamp: timestamp,
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
		Timestamp: timestamp,
		Signature: sig,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	// 6. Envoyer la requête HTTP
	url := cfg.Server + "/api/command"
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
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

// buildTLSConfig prépare la vérification du certificat du core.
//
// # Ce qui a changé
//
// La configuration était :
//
//	&tls.Config{InsecureSkipVerify: true}  // ⚠️ en prod remplacer par vérif réelle
//
// Le commentaire reconnaissait le problème. Cet outil parle à l'API
// d'administration : accepter n'importe quel certificat y revient à accepter
// n'importe quel interlocuteur, sur le canal qui porte les gestes les plus
// lourds du système.
//
// # Le certificat auto-signé n'est pas un obstacle
//
// Le core en génère un par défaut. Il suffit de le déclarer dans la
// configuration — c'est ce que fait ca_certificate — et la vérification
// redevient possible sans autorité publique.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.InsecureSkipVerify {
		// Bruyant volontairement : ce mode ne doit pas s'oublier. Un outil qui
		// n'authentifie plus son interlocuteur sans le dire est plus dangereux
		// qu'un outil qui refuse de fonctionner.
		fmt.Fprintln(os.Stderr,
			"⚠  vérification du certificat DÉSACTIVÉE (insecure_skip_verify) — diagnostic uniquement")
		return &tls.Config{InsecureSkipVerify: true}, nil
	}

	if cfg.CACertificate == "" {
		// Magasin du système. Suffisant si le certificat du core est signé par
		// une autorité reconnue, ou si son certificat auto-signé y a été
		// importé.
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}

	pem, err := os.ReadFile(cfg.CACertificate)
	if err != nil {
		return nil, fmt.Errorf("certificat d'autorité illisible (%s) : %v", cfg.CACertificate, err)
	}

	// On PART du magasin système et on y ajoute, plutôt que de le remplacer :
	// remplacer ferait perdre toutes les autorités publiques, et casserait la
	// vérification le jour où le core passe à un certificat signé.
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("aucun certificat exploitable dans %s", cfg.CACertificate)
	}

	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
