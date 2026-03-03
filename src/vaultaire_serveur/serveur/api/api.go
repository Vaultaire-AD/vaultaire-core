package api

import (
	"vaultaire/serveur/command"
	"vaultaire/serveur/database"
	dbuser "vaultaire/serveur/database/db-user"
	"vaultaire/serveur/global/security"
	"vaultaire/serveur/logs"
	duckykey "vaultaire/serveur/ducky-network/key_management"
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
	requestID := r.Header.Get("X-Request-ID")

	req, err := decodeRequest(r)
	if err != nil {
		logRequest(requestID, 0, req, "", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID, err := fetchUserID(req.Username)
	if err != nil {
		logRequest(requestID, 0, req, "", err)
		http.Error(w, "Utilisateur introuvable", http.StatusUnauthorized)
		return
	}

	pubKeys, err := dbuser.GetUserKeys(userID)
	if err != nil || len(pubKeys) == 0 {
		logRequest(requestID, userID, req, "", err)
		http.Error(w, "Aucune clé publique trouvée", http.StatusUnauthorized)
		return
	}

	bodyToVerify, err := buildSignedBody(req)
	if err != nil {
		logRequest(requestID, userID, req, "", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

	if !verifySignature(pubKeys, bodyToVerify, req.Signature) {
		err = fmt.Errorf("signature invalide")
		logRequest(requestID, userID, req, "", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	result := command.ExecuteCommand(req.Command, req.Username)
	logRequest(requestID, userID, req, result, nil)
	writeJSON(w, CommandResponse{Result: result})
}

// logRequest logs one API command line with request_id and user_id (specific errors are already logged by decodeRequest etc.).
func logRequest(requestID string, userID int, req *CommandRequest, result string, err error) {
	username := "<unknown>"
	commandStr := "<empty>"
	if req != nil {
		username = req.Username
		commandStr = req.Command
	}
	level := "INFO"
	msg := "api: command user=" + username + " command=" + commandStr + " status=success"
	if err != nil {
		level = "ERROR"
		msg = "api: command failed user=" + username + " error=" + err.Error()
	}
	meta := logs.WithMeta(requestID, strconv.Itoa(userID))
	if meta == nil && userID > 0 {
		meta = logs.UserMeta(userID)
	}
	logs.Write_LogCodeMeta(level, logs.CodeNone, msg, meta)
}

// ===================== SOUS-FONCTIONS =====================

// decodeRequest lit et parse la requête JSON
func decodeRequest(r *http.Request) (*CommandRequest, error) {
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPIDecode, "api: JSON decode failed: "+err.Error())
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
		logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: signed body build failed: "+err.Error())
		return nil, err
	}
	return body, nil
}

// verifySignature vérifie la signature avec toutes les clés
func verifySignature(pubKeys []storage.PublicKey, body []byte, sigB64 string) bool {
	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: signature base64 decode failed: "+err.Error())
		return false
	}

	var sig ssh.Signature
	if err := ssh.Unmarshal(sigRaw, &sig); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: signature SSH unmarshal failed: "+err.Error())
		return false
	}

	success := false

	for i, k := range pubKeys {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Key))
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeAPISign, fmt.Sprintf("api: public key #%d invalid: %s", i, err))
			continue
		}

		if err := pub.Verify(body, &sig); err != nil {
			logs.Write_Log("DEBUG", fmt.Sprintf("api: public key #%d verify failed: %s", i, err))
		} else {
			success = true
			break
		}
	}

	if !success {
		logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: no public key validated the signature")
	}

	return success
}

// writeJSON renvoie la réponse JSON
func writeJSON(w http.ResponseWriter, resp CommandResponse) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPIDecode, "api: JSON write failed: "+err.Error())
	}
}

// ===================== SERVEUR API =====================

func StartAPI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/command", commandHandler)

	certPEM, keyPEM, err := duckykey.GetCertificatePEMFromDB(duckykey.APIServerCertName)
	if err != nil {
		certPEM, keyPEM, err = security.GenerateSelfSignedCertPEM()
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeAPITLS, "api: certificate generation failed: "+err.Error())
			return
		}
		if errSave := duckykey.SaveCertificateToDB(duckykey.APIServerCertName, "tls_cert", "Certificat TLS API REST", certPEM, keyPEM); errSave != nil {
			certPEM, keyPEM, err = duckykey.GetCertificatePEMFromDB(duckykey.APIServerCertName)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeCertLoad, "api: certificate load from database failed: "+err.Error())
				return
			}
		}
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPITLS, "api: TLS certificate load failed: "+err.Error())
		return
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:      ":" + strconv.Itoa(storage.API_Port),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	logs.Write_Log("INFO", "api: REST HTTPS listening on port "+strconv.Itoa(storage.API_Port))

	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(storage.API_Port), tlsConfig)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPITLS, "api: TLS listen failed: "+err.Error())
		return
	}
	if err := server.Serve(listener); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPITLS, "api: server serve failed: "+err.Error())
	}
}
