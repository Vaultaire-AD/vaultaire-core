package userauth

import (
	"fmt"
	"strings"
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/gpo"
	"vaultaire_client/logs"
	"vaultaire_client/sessionmgr"
	"vaultaire_client/storage"
	sto_session "vaultaire_client/storage/stosession"
	"vaultaire_client/tools/getlocalinformation"
	"vaultaire_client/tools/sshreq"
)

func AskAuthentification(username string, password string, duckysession *storage.DuckySession) {
	message := fmt.Sprintf("02_01\nserveur_central\n%s\n%s\n%s\n%s", duckysession.SessionKey, username, storage.Computeur_ID, password)
	sendmessage.SendMessage(message, duckysession)
	duckysession.IsSafe = true
}

func User_Auth_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	message := ""

	switch trames_content.Message_Order[1] {

	case "02":
		return "02_03\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" +
			trames_content.Username + "\n" +
			storage.Computeur_ID + "\n" +
			trames_content.Content

	case "04":
		lines := strings.Split(trames_content.Content, "\n")
		username := lines[0]

		// AES
		content := strings.Join(lines[5:], "\n")
		storage.AES_key = []byte(content)

		// PAM status
		storage.Authentification_PAM <- "success"

		// admin
		storage.IsAdmin = (lines[1] == "true")

		rep := storage.AuthResult{
			IsAdmin: storage.IsAdmin,
			Keys:    lines[2],
		}
		// 🔑 SSH KEYS → nouveau système
		if lines[2] != "empty" {
			if ch, ok := sshreq.Pop(username); ok {
				select {
				case ch <- rep:
				default:
					logs.Write_log("WARNING", "Channel SSH plein pour "+username)
				}
			}
		}

		logs.Write_log("INFO", username+" authentifié succès admin="+lines[1])

		activeSession, _ := getlocalinformation.GetActiveUsers()

		message = "02_12\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" +
			username + "\n" +
			storage.Computeur_ID + "\n" +
			getlocalinformation.GetAllLocalInfForServeur() + "\n" +
			strings.Join(activeSession, ",")

		sendmessage.SendMessage(message, duckysession)

		message = "02_15\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" +
			username + "\n" +
			storage.Computeur_ID + "\nask_gpo"

	case "16":
		lines := strings.Split(trames_content.Content, "\n")
		username := lines[0]

		for i := 1; i < len(lines); i++ {
			err := gpo.ApplyGPOsAsUser(username, lines[i])
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur GPO : %v", err))
			}
		}

	case "07":
		lines := strings.Split(trames_content.Content, "\n")
		logs.Write_log("WARNING",
			fmt.Sprintf("Authentification failed for user %s : %s", lines[0], lines[1]))
		storage.Authentification_PAM <- "failed"

	case "11":
		lines := strings.Split(trames_content.Content, "\n")
		username := lines[0]

		logs.Write_log("INFO", "client online")

		activeSession, _ := getlocalinformation.GetActiveUsers()

		sto_session.SessionsUser.AddOrUpdate(
			username,
			duckysession.Conn,
			sessionmgr.SessionAuthenticated,
			duckysession,
		)

		message = "02_12\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" +
			"vaultaire\n" +
			storage.Computeur_ID + "\n" +
			getlocalinformation.GetAllLocalInfForServeur() + "\n" +
			strings.Join(activeSession, ",")

	}

	return message
}
