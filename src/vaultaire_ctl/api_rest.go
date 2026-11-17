package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// vaultairectl api — appeler l'API REST (TO-DO 270).
//
//	vaultairectl api GET  /api/v1/users
//	vaultairectl api POST /api/v1/users '{"username":"bob","domain":"acme.lan","password":"…","birthdate":"01/01/1990"}'
//	vaultairectl api POST /api/v1/groups @groupe.json        (corps lu dans un fichier ; « @- » : l'entrée standard)
//	vaultairectl api --headers GET /api/v1/users             (les en-têtes signés, pour curl)
//
// La signature est celle du serveur (core/api/rest_auth.go, ChaineCanoniqueREST) :
// les deux doivent rester identiques octet pour octet — un test de chaque côté
// fige la même chaîne.

const prefixeCanoniqueREST = "VAULTAIRE-REST-1"

// chaineCanoniqueREST : COPIE de core/api.ChaineCanoniqueREST.
func chaineCanoniqueREST(methode, chemin, requete, compte string, horodatage int64, nonce string, corps []byte) []byte {
	somme := sha256.Sum256(corps)
	return []byte(strings.Join([]string{
		prefixeCanoniqueREST,
		strings.ToUpper(methode),
		chemin,
		requete,
		compte,
		strconv.FormatInt(horodatage, 10),
		nonce,
		hex.EncodeToString(somme[:]),
	}, "\n"))
}

func aideAPI() {
	fmt.Fprintln(os.Stderr, `Usage : vaultairectl api [--headers] <MÉTHODE> <chemin> [corps JSON | @fichier | @-]

  vaultairectl api GET /api/v1/users
  vaultairectl api PUT /api/v1/groups/infra/users/bob
  vaultairectl api POST /api/v1/actions/settings.list '{}'
  vaultairectl api GET /api/v1/openapi.json

  --headers  n'envoie rien : écrit les en-têtes signés (pour curl -H).
             Le corps doit alors être envoyé tel quel, octet pour octet.

Sortie : la réponse JSON du core. Code de retour 0 si "ok": true.`)
}

// lancerAPI est l'entrée de « vaultairectl api ».
func lancerAPI(args []string) int {
	entetesSeuls := false
	if len(args) > 0 && args[0] == "--headers" {
		entetesSeuls = true
		args = args[1:]
	}
	if len(args) < 2 || len(args) > 3 {
		aideAPI()
		return 2
	}
	methode := strings.ToUpper(args[0])
	chemin := args[1]
	var corps []byte
	if len(args) == 3 {
		var err error
		if corps, err = lireCorps(args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "❌", err)
			return 2
		}
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "❌", err)
		return 1
	}
	priv, err := loadPrivateKey(cfg.PrivateKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "❌ erreur clé privée:", err)
		return 1
	}

	cible, err := url.Parse(strings.TrimRight(cfg.Server, "/") + chemin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "❌ chemin invalide:", err)
		return 2
	}

	horodatage := time.Now().Unix()
	nonce := generateNonce()
	sig, err := signMessage(priv, chaineCanoniqueREST(methode, cible.EscapedPath(), cible.RawQuery,
		cfg.Username, horodatage, nonce, corps))
	if err != nil {
		fmt.Fprintln(os.Stderr, "❌ erreur signature:", err)
		return 1
	}
	entetes := map[string]string{
		"Authorization":         "Vaultaire-SSH " + sig,
		"X-Vaultaire-User":      cfg.Username,
		"X-Vaultaire-Timestamp": strconv.FormatInt(horodatage, 10),
		"X-Vaultaire-Nonce":     nonce,
	}
	if len(corps) > 0 {
		entetes["Content-Type"] = "application/json"
	}

	if entetesSeuls {
		// Valables deux minutes, et une seule fois (nonce).
		for _, k := range []string{"Authorization", "X-Vaultaire-User", "X-Vaultaire-Timestamp", "X-Vaultaire-Nonce", "Content-Type"} {
			if v, ok := entetes[k]; ok {
				fmt.Printf("%s: %s\n", k, v)
			}
		}
		return 0
	}

	req, err := http.NewRequest(methode, cible.String(), bytes.NewReader(corps))
	if err != nil {
		fmt.Fprintln(os.Stderr, "❌", err)
		return 2
	}
	for k, v := range entetes {
		req.Header.Set(k, v)
	}
	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "❌", err)
		return 1
	}
	client := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "❌ erreur requête:", err)
		return 1
	}
	defer resp.Body.Close()
	brut, _ := io.ReadAll(resp.Body)

	// Indenté pour la lecture ; tel quel si ce n'est pas du JSON.
	var joli bytes.Buffer
	if json.Indent(&joli, brut, "", "  ") == nil {
		fmt.Println(joli.String())
	} else {
		fmt.Println(string(brut))
	}

	var rep struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(brut, &rep) == nil && rep.OK {
		return 0
	}
	if resp.StatusCode < 300 && chemin == "/api/v1/openapi.json" {
		return 0
	}
	return 1
}

func lireCorps(arg string) ([]byte, error) {
	var b []byte
	var err error
	switch {
	case arg == "@-":
		b, err = io.ReadAll(os.Stdin)
	case strings.HasPrefix(arg, "@"):
		b, err = os.ReadFile(arg[1:])
	default:
		b = []byte(arg)
	}
	if err != nil {
		return nil, err
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("corps : JSON invalide")
	}
	return b, nil
}
