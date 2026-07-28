package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/duckynetworkClient/userauth"
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
	saltChan := make(chan storage.AuthResult, 1)
	sshreq.Register(req.User, saltChan)
	defer sshreq.Remove(req.User)

	// 3. Appel vers le serveur backend Vaultaire
	if tools.IsDuckySessionActive() {

	} else {
		go serveurcommunication.EnableServerCommunication("vaultaire", "vaultaire")
		time.Sleep(500 * time.Millisecond) // Attente pour que le serveur traite la requete
	}
	//----------------------------------------
	// --- Etape 1 : demande du salt/nonce ---
	//----------------------------------------
	var msg = "03_04\nserveur_central\n" + string(storage.DuckySessionLive.SessionKey) + "\n" + "vaultaire" + "\n" + storage.Computeur_ID + "\n" + req.User
	sendmessage.SendMessage(msg, storage.DuckySessionLive)

	// 4. Attente du resultat ou du Timeout
	statusRep := "failed"
	var salt, nonce string
	isAdminResult := false
	var sshKeys []string

	select {
	case result := <-saltChan:
		sshreq.Remove(req.User) // le Pop côté serveur l'a déjà retiré, mais on nettoie par sécurité
		if result.Type != "SALT" {
			logs.Write_log("WARNING", fmt.Sprintf("[%s] Type inattendu en etape 1 pour %s: %s", reqType, req.User, result.Type))
			sendResponse(conn, Response{Status: "failed"})
			return
		}
		salt = result.Salt
		nonce = result.Nonce
		logs.Write_log("INFO", fmt.Sprintf("[%s] Salt/Nonce recus pour %s", reqType, req.User))

	case <-time.After(7 * time.Second):
		logs.Write_log("ERROR", fmt.Sprintf("[%s] Timeout lors de l'auth pour %s", reqType, req.User))
		statusRep = "timeout"
		return
	}
	// --- Calcul de la preuve ---
	proof, err := userauth.GenerateChallengeProof(req.User, req.Password, salt, nonce, string(storage.DuckySessionLive.SessionKey))
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("[%s] Erreur generation proof pour %s: %v", reqType, req.User, err))
		sendResponse(conn, Response{Status: "failed"})
		return
	}
	finalChan := make(chan storage.AuthResult, 1)
	sshreq.Register(req.User, finalChan)
	defer sshreq.Remove(req.User)

	// ⚠️ ordre de message a confirmer (celui qui route vers SSH_SEND_Pubkey_AUTH côté serveur)
	proofMsg := "03_01\nserveur_central\n" + string(storage.DuckySessionLive.SessionKey) + "\nvaultaire\n" + storage.Computeur_ID + "\n" + req.User + "\n" + proof
	sendmessage.SendMessage(proofMsg, storage.DuckySessionLive)
	//----------------------------------------------------------------
	// --- Etape 2 : envoi de la preuve, attente du resultat final ---
	//----------------------------------------------------------------
	select {
	case result := <-finalChan:
		if result.Type != "" && result.Type != "AUTH" {
			logs.Write_log("WARNING", fmt.Sprintf("[%s] Mismatch de type en etape 2 pour %s: recu %s",
				reqType, req.User, result.Type))
			statusRep = "failed"
		} else {
			statusRep = "success"
			isAdminResult = result.IsAdmin
			sshKeys = parseSSHKeys(result.SSHKeys)
			logs.Write_log("INFO", fmt.Sprintf("[%s] Auth finale reussie pour %s (Admin: %t, Cles: %d)",
				reqType, req.User, isAdminResult, len(sshKeys)))
		}

	case <-time.After(7 * time.Second):
		logs.Write_log("ERROR", fmt.Sprintf("[%s] Timeout etape 2 (proof) pour %s", reqType, req.User))
		statusRep = "timeout"
	}

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
