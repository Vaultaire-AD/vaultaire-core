package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	duckytool "vaultaire_client/duckynetworkClient/ducky_tool"
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/duckynetworkClient/userauth"
	"vaultaire_client/gpo"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
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

	sess := duckytool.OpenVaultaireDefaultSession()
	//----------------------------------------
	// --- Etape 1 : demande du salt/nonce ---
	//----------------------------------------
	var msg = "03_04\nserveur_central\n" + string(sess.DuckySession.SessionKey) + "\n" + "vaultaire" + "\n" + storage.Computeur_ID + "\n" + req.User
	sendmessage.SendMessage(msg, sess.DuckySession)

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
	proof, err := userauth.GenerateChallengeProof(req.User, req.Password, salt, nonce, string(sess.DuckySession.SessionKey))
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("[%s] Erreur generation proof pour %s: %v", reqType, req.User, err))
		sendResponse(conn, Response{Status: "failed"})
		return
	}
	finalChan := make(chan storage.AuthResult, 1)
	sshreq.Register(req.User, finalChan)
	defer sshreq.Remove(req.User)

	// ⚠️ ordre de message a confirmer (celui qui route vers SSH_SEND_Pubkey_AUTH côté serveur)
	logs.Write_log("DEBUG", fmt.Sprintf("CLIENT SOFTWARE ID: %s", storage.Computeur_ID))
	proofMsg := sendmessage.BuildClientTrame("03_01", "serveur_central", string(sess.DuckySession.SessionKey), "vaultaire", storage.Computeur_ID, req.User, proof)
	sendmessage.SendMessage(proofMsg, sess.DuckySession)
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
			logs.Write_log("INFO", fmt.Sprintf("[%s] Reponse du serveur central recue %s (Admin: %t, Cles: %d)",
				reqType, req.User, isAdminResult, len(sshKeys)))
		}

	case <-time.After(7 * time.Second):
		logs.Write_log("ERROR", fmt.Sprintf("[%s] Timeout etape 2 (proof) pour %s", reqType, req.User))
		statusRep = "timeout"
	}

	// GPO de scope user : le compte local est provisionné (fait à la réception de
	// 03_02) et l'authentification est validée, mais le droit de connexion n'est
	// pas encore rendu à PAM. C'est le seul moment où l'utilisateur trouvera son
	// environnement en place dès l'ouverture de session.
	//
	// Le cycle est lancé ICI et non dans le gestionnaire de trames : ce dernier
	// tourne dans la goroutine qui lit la connexion, et y attendre une réponse du
	// serveur bloquerait la lecture de cette même réponse. Cette goroutine-ci est
	// indépendante du lecteur, elle peut donc attendre sans rien bloquer.
	if statusRep == "success" {
		applyUserGPO(req.User, string(sess.DuckySession.SessionKey))
	}

	sendResponse(conn, Response{
		Status:  statusRep,
		IsAdmin: isAdminResult,
		SSHKeys: sshKeys,
	})
}

// applyUserGPO applique les GPO de scope user avant de rendre la main à PAM.
//
// Un échec ou un dépassement du délai n'empêche PAS la connexion : aucun module
// de scope user ne touche aux privilèges, alors qu'un annuaire qui bloque les
// connexions sur incident GPO serait un incident d'exploitation majeur.
// L'incident part dans les journaux et dans le rapport 05_12.
func applyUserGPO(username, sessionKey string) {
	if sessionKey == "" {
		logs.Write_log("WARNING", "GPO: pas de cle de session, GPO user non appliquees pour "+username)
		return
	}

	logs.Write_log("DEBUG", "GPO: application des GPO user pour "+username+" avant octroi de la connexion")
	report := gpo.RunUserCycle(sessionKey, username)

	if report.Status != gpo.StatusApplied {
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: politique user incomplete pour %s, connexion tout de meme accordee — %s",
			username, report.Summary()))
	}
}

// Helper interne d'envoi JSON vers le socket PAM
func sendResponse(conn net.Conn, resp Response) {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(resp); err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur envoi reponse PAM: %v", err))
	}
}
