package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"vaultaire_client/logs"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/storage"
	"vaultaire_client/tools"
	"vaultaire_client/tools/sshreq"
)

func processPamRequest(conn net.Conn, reqType string, payload string) {
	var req PamPayload
	err := json.Unmarshal([]byte(payload), &req)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("[%s] Erreur decodage JSON: %v", reqType, err))
		return
	}

	// Invalidation de la memoire du mot de passe en fin de fonction
	defer func() {
		req.Password = ""
	}()

	// 1. Validation des champs
	if !isValidUserInput(req.User) {
		logs.Write_log("ERROR", fmt.Sprintf("[%s] Nom d'utilisateur invalide: %s", reqType, req.User))
		sendResponse(conn, Response{Status: "failed"})
		return
	}

	logs.Write_log("INFO", fmt.Sprintf("[%s] Requete recue pour l'utilisateur: %s", reqType, req.User))

	// 2. Enregistrement du canal de reponse pour async/concurrence
	respChan := make(chan storage.AuthResult, 1)
	sshreq.Register(req.User, respChan)
	defer sshreq.Remove(req.User)

	// 3. Appel vers le serveur backend Vaultaire
	if tools.IsDuckySessionActive() {

	} else {
		go serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire", req.User, &req.Password, false)
	}

	// 4. Attente du resultat ou du Timeout
	statusRep := "failed"
	isAdminResult := false
	var sshKeys []string

	select {
	case result := <-respChan:
		// Vérification explicite : le type reçu correspond-il au type demandé ?
		if result.Type != "" && result.Type != reqType {
			logs.Write_log("WARNING", fmt.Sprintf("[%s] Mismatch de type recu pour %s: attendu %s, recu %s",
				reqType, req.User, reqType, result.Type))
			statusRep = "failed"
		} else {
			statusRep = "success"
			isAdminResult = result.IsAdmin
			sshKeys = parseSSHKeys(result.SSHKeys)

			logs.Write_log("INFO", fmt.Sprintf("[%s] Auth succes pour %s (Type: %s, Admin: %t, Cles: %d)",
				reqType, req.User, result.Type, isAdminResult, len(sshKeys)))
		}

	case <-time.After(7 * time.Second):
		logs.Write_log("ERROR", fmt.Sprintf("[%s] Timeout lors de l'auth pour %s", reqType, req.User))
		statusRep = "timeout"
	}

	// 5. Envoi de la reponse JSON
	sendResponse(conn, Response{
		Status:  statusRep,
		IsAdmin: isAdminResult,
		SSHKeys: sshKeys,
	})
}

// Helper interne d'envoi JSON vers le socket PAM
func sendResponse(conn net.Conn, resp Response) {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(resp); err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur envoi reponse PAM: %v", err))
	}
}
