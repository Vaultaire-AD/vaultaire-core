package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
	"vaultaire_client/pamstate"

	duckytool "duckynetworkclient/V1/duckynetwork/ducky_tool"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"vaultaire_client/gpo"
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
	finalChan := make(chan pamstate.AuthResult, 1)
	sshreq.Register(req.User, finalChan)
	defer sshreq.Remove(req.User)

	statusRep := "failed"
	isAdminResult := false
	// Non nil dès le départ : voir parseSSHKeys, une tranche nil se sérialise en
	// `null` et le module PAM y lit « réponse illisible », donc « ne touche pas
	// à authorized_keys ».
	sshKeys := []string{}

	sess := duckytool.OpenVaultaireDefaultSession()

	// --- UN SEUL aller-retour : le mot de passe, dans le tunnel ---
	//
	// L'échange en comptait deux. Le poste demandait d'abord le SEL du compte
	// (03_04), le serveur le lui donnait avec un nonce (03_05), et le poste
	// renvoyait un HMAC calculé avec SHA-256(sel‖mot de passe) pour clé. Le mot
	// de passe ne quittait jamais la machine.
	//
	// Ce que cela coûtait est invisible d'ici : pour recalculer ce HMAC, le
	// serveur devait détenir la même clé, donc STOCKER cette clé. L'empreinte en
	// base était donc directement rejouable — la lire suffisait à ouvrir une
	// session SSH sur le compte, sans connaître le mot de passe. Le hachage ne
	// protégeait rien sur ce chemin, et interdisait de passer à argon2id.
	//
	// Le mot de passe transite maintenant comme sur les trois autres portes du
	// serveur — portail web, bind LDAP, trame 02_03 — c'est-à-dire à l'intérieur
	// de la session Ducky, déjà chiffrée et authentifiée. Le serveur vérifie
	// seul, et l'empreinte redevient une empreinte.
	//
	// Effet de bord : plus de premier aller-retour, donc une ouverture de session
	// plus courte et une fenêtre de moins où l'échange pouvait rester en plan.
	logs.Write_log("DEBUG", fmt.Sprintf("CLIENT SOFTWARE ID: %s", storage.Computeur_ID))
	authMsg := sendmessage.BuildClientTrame("03_01", "serveur_central",
		string(sess.DuckySession.SessionKey), "vaultaire", storage.Computeur_ID,
		req.User, req.Password)
	sendmessage.SendMessage(authMsg, sess.DuckySession)

	//----------------------------------------------------------------
	// --- Attente du resultat final ---
	//----------------------------------------------------------------
	select {
	case result, recu := <-finalChan:
		motif := VerdictRefuse(result, recu)
		if motif != "" {
			logs.Write_log("WARNING", fmt.Sprintf(
				"[%s] Authentification REFUSEE pour %s : %s", reqType, req.User, motif))
			statusRep = "failed"
			break
		}

		statusRep = "success"
		isAdminResult = result.IsAdmin
		sshKeys = parseSSHKeys(result.SSHKeys)
		logs.Write_log("INFO", fmt.Sprintf("[%s] Reponse du serveur central recue %s (Admin: %t, Cles: %d)",
			reqType, req.User, isAdminResult, len(sshKeys)))

	case <-time.After(7 * time.Second):
		logs.Write_log("ERROR", fmt.Sprintf("[%s] Timeout d'authentification pour %s", reqType, req.User))
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
