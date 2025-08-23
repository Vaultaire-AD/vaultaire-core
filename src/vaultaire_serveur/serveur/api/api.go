package api

import (
	"DUCKY/serveur/command"
	"DUCKY/serveur/database"
	dbuser "DUCKY/serveur/database/db-user"
	"DUCKY/serveur/global/security"
	"DUCKY/serveur/global/security/keymanagement"
	"DUCKY/serveur/storage"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// Requête attendue du client
type CommandRequest struct {
	Username  string `json:"username"`
	Command   string `json:"command"`
	Signature string `json:"signature"` // en base64
}

type CommandResponse struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// handler REST qui appelle ton dispatcher
func commandHandler(w http.ResponseWriter, r *http.Request) {
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	fmt.Printf("Requête reçue : %+v\n", req.Command)
	fmt.Printf("Utilisateur : %+v\n", req.Username)
	fmt.Printf("Signature (base64) : %+v\n", req.Signature)
	// 1. Récupérer l'ID de l'utilisateur
	usernameId, err := database.Get_User_ID_By_Username(database.GetDatabase(), strings.TrimSpace(req.Username))
	if err != nil {
		http.Error(w, "Utilisateur introuvable", http.StatusUnauthorized)
		return
	}

	// 2. Récupérer toutes les clés publiques de l'utilisateur
	pubKeys, err := dbuser.GetUserKeys(usernameId)
	if err != nil || len(pubKeys) == 0 {
		http.Error(w, "Aucune clé publique trouvée", http.StatusUnauthorized)
		return
	}

	// 3. Décoder la signature
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Signature mal formée", http.StatusBadRequest)
		return
	}

	// 4. Recréer le JSON exact qui a été signé côté client
	bodyToVerify, err := json.Marshal(struct {
		Command  string `json:"command"`
		Username string `json:"username"`
	}{
		Command:  req.Command,
		Username: req.Username,
	})
	if err != nil {
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

	// 5. Vérifier la signature avec toutes les clés
	valid := false
	hashed := sha256.Sum256(bodyToVerify)

	for _, k := range pubKeys {
		// TODO: parser la clé publique depuis k.Key en *rsa.PublicKey
		pubKey, err := keymanagement.ParseRSAPublicKeyFromPEM(k.Key)
		if err != nil {
			continue // ignorer les clés invalides
		}

		if rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sig) == nil {
			valid = true
			break
		}
	}

	if !valid {
		http.Error(w, "Signature invalide", http.StatusUnauthorized)
		return
	}

	// 5. Exécuter la commande si au moins une clé valide
	result := command.ExecuteCommand(req.Command)
	resp := CommandResponse{Result: result}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func StartAPI() {
	// Crée un mux et ajoute ton endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/api/command", commandHandler)

	privateKeyPath, _, err := keymanagement.Generate_Serveur_Key_Pair("api_server")
	if err != nil {
		log.Fatalf("Erreur génération paire de clés API : %v", err)
		return
	}
	certFile, err := security.GenerateSelfSignedCert(privateKeyPath, "api-server_cert")
	if err != nil {
		log.Fatalf("Erreur génération certificat : %v", err)
	}

	// Configuration TLS (sécurisée mais simple)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      ":" + strconv.Itoa(storage.API_Port),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	fmt.Println("🚀 API REST en HTTPS sur https://localhost:" + strconv.Itoa(storage.API_Port))
	log.Fatal(server.ListenAndServeTLS(certFile, privateKeyPath))
}
