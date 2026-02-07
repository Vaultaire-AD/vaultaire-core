package api

import (
	"vaultaire/serveur/command"
	"vaultaire/serveur/database"
	dbuser "vaultaire/serveur/database/db-user"
	"vaultaire/serveur/global/security"
	"vaultaire/serveur/global/security/keymanagement"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// CommandRequest représente la requête JSON du client
type CommandRequest struct {
	Username  string `json:"username"`
	Command   string `json:"command"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"` // en base64
}

// CommandResponse est renvoyée au client
type CommandResponse struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// ===================== HANDLER PRINCIPAL =====================

func commandHandler(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		logRequest(req, "", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID, err := fetchUserID(req.Username)
	if err != nil {
		logRequest(req, "", err)
		http.Error(w, "Utilisateur introuvable", http.StatusUnauthorized)
		return
	}

	pubKeys, err := dbuser.GetUserKeys(userID)
	if err != nil || len(pubKeys) == 0 {
		logRequest(req, "", err)
		http.Error(w, "Aucune clé publique trouvée", http.StatusUnauthorized)
		return
	}

	bodyToVerify, err := buildSignedBody(req)
	if err != nil {
		logRequest(req, "", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

	if !verifySignature(pubKeys, bodyToVerify, req.Signature) {
		err = fmt.Errorf("signature invalide")
		logRequest(req, "", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Exécution de la commande
	result := command.ExecuteCommand(req.Command, req.Username)

	// Log la requête avec succès
	logRequest(req, result, nil)

	writeJSON(w, CommandResponse{Result: result})
}

// logRequest enregistre la requête, le username, la commande et le résultat ou erreur
func logRequest(req *CommandRequest, result string, err error) {
	username := "<unknown>"
	commandStr := "<empty>"
	status := "SUCCESS"

	if req != nil {
		username = req.Username
		commandStr = req.Command
	}

	if err != nil {
		status = "ERROR: " + err.Error()
	}

	logs.Write_Log("INFO", "🕵️ User: "+username+" | Command: "+commandStr+" | Status: "+status)
}

// ===================== SOUS-FONCTIONS =====================

// decodeRequest lit et parse la requête JSON
func decodeRequest(r *http.Request) (*CommandRequest, error) {
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logs.Write_Log("ERROR", "Erreur décodage JSON: "+err.Error())
		return nil, err
	}
	return &req, nil
}

// fetchUserID retourne l’ID utilisateur depuis son username
func fetchUserID(username string) (int, error) {
	return database.Get_User_ID_By_Username(database.GetDatabase(), strings.TrimSpace(username))
}

// buildSignedBody reconstruit le JSON que le client a signé
func buildSignedBody(req *CommandRequest) ([]byte, error) {
	body, err := json.Marshal(struct {
		Command  string `json:"command"`
		Username string `json:"username"`
		Nonce    string `json:"nonce"`
	}{
		Command:  req.Command,
		Username: req.Username,
		Nonce:    req.Nonce,
	})
	if err != nil {
		logs.Write_Log("ERROR", "Erreur génération body signé: "+err.Error())
		return nil, err
	}
	return body, nil
}

// verifySignature vérifie la signature avec toutes les clés
func verifySignature(pubKeys []storage.PublicKey, body []byte, sigB64 string) bool {
	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		logs.Write_Log("ERROR", "Impossible de décoder la signature base64: "+err.Error())
		return false
	}

	var sig ssh.Signature
	if err := ssh.Unmarshal(sigRaw, &sig); err != nil {
		logs.Write_Log("ERROR", "Impossible de unmarshal la signature SSH: "+err.Error())
		return false
	}

	success := false

	for i, k := range pubKeys {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Key))
		if err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Clé publique #%d invalide, ignorée: %s", i, err))
			continue
		}

		if err := pub.Verify(body, &sig); err != nil {
			logs.Write_Log("WARN", fmt.Sprintf("Clé publique #%d échoue à vérifier la signature: %s", i, err))
		} else {
			logs.Write_Log("INFO", fmt.Sprintf("Signature valide avec la clé publique #%d", i))
			success = true
			break
		}
	}

	if !success {
		logs.Write_Log("ERROR", "Aucune clé publique n'a validé la signature !")
	}

	return success
}

// writeJSON renvoie la réponse JSON
func writeJSON(w http.ResponseWriter, resp CommandResponse) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logs.Write_Log("ERROR", "Erreur écriture JSON: "+err.Error())
	}
}

// ===================== SERVEUR API =====================

func StartAPI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/command", commandHandler)

	privateKeyPath, _, err := keymanagement.Generate_Serveur_Key_Pair("api_server")
	if err != nil {
		logs.Write_Log("ERROR", "Erreur génération paire de clés API: "+err.Error())
		return
	}

	certFile, err := security.GenerateSelfSignedCert(privateKeyPath, "api-server_cert")
	if err != nil {
		logs.Write_Log("ERROR", "Erreur génération certificat: "+err.Error())
		return
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	server := &http.Server{
		Addr:      ":" + strconv.Itoa(storage.API_Port),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	logs.Write_Log("INFO", "🚀 API REST en HTTPS sur https://localhost:"+strconv.Itoa(storage.API_Port))

	if err := server.ListenAndServeTLS(certFile, privateKeyPath); err != nil {
		logs.Write_Log("ERROR", "Erreur lancement serveur API: "+err.Error())
	}
}
