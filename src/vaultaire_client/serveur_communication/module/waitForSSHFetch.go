package module

import (
	"fmt"
	"time"
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/logs"
	"vaultaire_client/sessionmgr"
	"vaultaire_client/storage"
	"vaultaire_client/storage/stosession"
	"vaultaire_client/tools/sshreq"
)

func WaitForSSHFetch(user string, sshUser string, ds *storage.DuckySession) {
	logs.Write_log("INFO", fmt.Sprintf("Attente de clé fetch pour requete SSH (%s)", sshUser))

	// 1. On prépare le canal de réception
	respChan := make(chan storage.AuthResult, 1)
	sshreq.Register(sshUser, respChan)

	// 2. Boucle d'attente du TUNNEL (on vérifie la session machine "user" qui est "vaultaire")
	tunnelReady := false
	for i := 0; i < 50; i++ { // Timeout de 10s (50 * 200ms)
		status, ok := stosession.SessionsUser.GetStatus(user) // "user" ici est "vaultaire"
		if ok && status == sessionmgr.SessionAuthenticated {
			tunnelReady = true
			break
		}
		if status == sessionmgr.SessionFailed {
			logs.Write_log("ERROR", "Le tunnel machine a échoué")
			return
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !tunnelReady {
		logs.Write_log("ERROR", "Le tunnel n'est pas devenu prêt à temps")
		return
	}

	// 3. Le tunnel est OK, on envoie la demande 03_04
	logs.Write_log("INFO", fmt.Sprintf("Tunnel OK, envoi demande 03_04 pour %s", sshUser))
	msg := fmt.Sprintf("03_04\nserveur_central\n%s\n%s\n%s\n%s",
		string(ds.SessionKey), user, storage.Computeur_ID, sshUser)
	sendmessage.SendMessage(msg, ds)

	// 4. 🔥 TRÈS IMPORTANT : On attend ici la réponse du Manager avant de quitter la fonction
	// C'est ce select qui va capturer ce que le SSH_Auth_Manager envoie
	select {
	case res, ok := <-respChan:
		if ok {

			// C'est ici que le binaire écrit les clés sur Stdout pour SSH
			fmt.Println(res.Keys)
			logs.Write_log("INFO", "Clés affichées avec succès")
		} else {
			logs.Write_log("ERROR", "Le channel SSH a été fermé sans données")
		}
	case <-time.After(10 * time.Second):
		logs.Write_log("ERROR", "Timeout : Le serveur central n'a pas répondu à la demande 03_04")
	}

	// La fonction se termine seulement après avoir reçu les clés ou timeout
}
