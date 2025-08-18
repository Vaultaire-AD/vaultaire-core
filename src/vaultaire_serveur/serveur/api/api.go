package api

import (
	"DUCKY/serveur/command"
	"DUCKY/serveur/global/security"
	"DUCKY/serveur/global/security/keymanagement"
	"DUCKY/serveur/storage"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

// Importe ton package de commandes
// import "tonmodule/commands"

type CommandRequest struct {
	Command string `json:"command"`
}

type CommandResponse struct {
	Result string `json:"result"`
}

// handler REST qui appelle ton dispatcher
func commandHandler(w http.ResponseWriter, r *http.Request) {
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

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
