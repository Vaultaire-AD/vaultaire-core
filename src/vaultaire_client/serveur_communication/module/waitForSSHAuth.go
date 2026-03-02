package module

import (
	"fmt"
	"time"
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/logs"
	"vaultaire_client/sessionmgr"
	"vaultaire_client/storage"
	"vaultaire_client/storage/stosession"
)

func WaitForSSHAuth(user string, sshUser string, sshpassword *string, ds *storage.DuckySession) {
	logs.Write_log("INFO", fmt.Sprintf("Attente authentification pour requete SSH (%s)", sshUser))

	for {
		status, ok := stosession.SessionsUser.GetStatus(user)
		if !ok {
			logs.Write_log("ERROR", "Session nettoyée prématurément")
			return
		}

		if status == sessionmgr.SessionAuthenticated {
			logs.Write_log("INFO", fmt.Sprintf("Session OK, envoi demande SSH pour %s", sshUser))
			msg := fmt.Sprintf("03_01\nserveur_central\n%s\n%s\n%s\nask_sshpubkey\n%s\n%s",
				string(ds.SessionKey), user, storage.Computeur_ID, sshUser, *sshpassword)
			sendmessage.SendMessage(msg, ds)
			return
		}

		if status == sessionmgr.SessionFailed {
			logs.Write_log("ERROR", "Authentification rejetée par le serveur")
			return
		}

		time.Sleep(200 * time.Millisecond)
	}
}
