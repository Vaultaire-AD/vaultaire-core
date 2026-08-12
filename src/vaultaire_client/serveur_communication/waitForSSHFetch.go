package serveurcommunication

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	sto_session "duckynetworkclient/V1/duckynetwork/storage/stosession"
	"fmt"
	"time"
	"vaultaire_client/pamstate"
	"vaultaire_client/tools/sshreq"
)

func WaitForSSHFetch(user string, sshUser string) {
	logs.Write_log("INFO", fmt.Sprintf("Attente de clé fetch pour requete SSH (%s)", sshUser))
	// 1. On prépare le canal de réception
	respChan := make(chan pamstate.AuthResult, 1)
	sshreq.Register(sshUser, respChan)

	// 2. Boucle d'attente du TUNNEL : on interroge le manager de sessions
	// pour une session "vaultaire" authentifiée et utilisable (il peut y en
	// avoir plusieurs ; on en prend une, la première valide).
	time.Sleep(1 * time.Second)
	sess, err := sto_session.SessionsUser.WaitForVaultaireSession()
	if err != nil {
		logs.Write_log("ERROR", "Timeout attente session Vaultaire")
		return
	}
	ds := sess.DuckySession
	// 3. Le tunnel est OK, on envoie la demande 03_06
	logs.Write_log("INFO", fmt.Sprintf("Tunnel OK, envoi demande 03_06 pour %s", sshUser))
	msg := fmt.Sprintf("03_06\nserveur_central\n%s\n%s\n%s\n%s", string(ds.SessionKey), user, storage.Computeur_ID, sshUser)
	sendmessage.SendMessage(msg, ds)

	// 4. 🔥 TRÈS IMPORTANT : On attend ici la réponse du Manager avant de quitter la fonction
	// C'est ce select qui va capturer ce que le SSH_Auth_Manager envoie
	select {
	case res, ok := <-respChan:
		if ok {

			// C'est ici que le binaire écrit les clés sur Stdout pour SSH
			fmt.Println(res.SSHKeys)
			logs.Write_log("INFO", "Clés affichées avec succès")
		} else {
			logs.Write_log("ERROR", "Le channel SSH a été fermé sans données")
		}
	case <-time.After(10 * time.Second):
		logs.Write_log("ERROR", "Timeout : Le serveur central n'a pas répondu à la demande 03_06")
	}
	msg = fmt.Sprintf("02_05\nserveur_central\n%s\n%s\n%s",
		string(ds.SessionKey), user, storage.Computeur_ID)
	sendmessage.SendMessage(msg, ds)
	// On ferme via RemoveSession (par SessionID) plutôt qu'un
	// storage.DuckySessionLive.Conn.Close() direct : ça évite de fermer une
	// connexion différente si une reconnexion a eu lieu entre-temps, et ça
	// nettoie la map au lieu de laisser une entrée fantôme jusqu'au prochain
	// timeout.
	stosession.SessionsUser.RemoveSession(ds.SessionID)
	logs.Write_log("INFO", fmt.Sprintf("Fin du WaitForSSHFetch pour %s (session id=%s)", sshUser, ds.SessionID))
}
