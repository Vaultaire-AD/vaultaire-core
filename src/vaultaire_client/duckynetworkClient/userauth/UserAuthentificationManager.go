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

		logs.Write_log("INFO", fmt.Sprintf("%s authentifié succès admin=%s (session id=%s)", username, lines[1], duckysession.SessionID))

		// Cette session a été enregistrée en Pending dès l'ouverture de la
		// connexion (EnableServerCommunication) ; on la marque Authenticated
		// maintenant que le serveur a confirmé le login.
		sto_session.SessionsUser.SetStatus(duckysession.SessionID, sessionmgr.SessionAuthenticated)
		sto_session.SessionsUser.Touch(duckysession.SessionID)
		activeSession, _ := getlocalinformation.GetActiveUsers()

		message = "02_12\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" +
			username + "\n" +
			storage.Computeur_ID + "\n" +
			getlocalinformation.GetAllLocalInfForServeur() + "\n" +
			strings.Join(activeSession, ",")

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
		// lines := strings.Split(trames_content.Content, "\n")
		// username := lines[0]
		activeSession, _ := getlocalinformation.GetActiveUsers()

		// logs.Write_log("INFO", fmt.Sprintf("%s en ligne (session id=%s)", username, duckysession.SessionID))

		// La session vaultaire a déjà été enregistrée (Pending) sous
		// MotherSessionID dès l'ouverture de la connexion ; on la passe
		// simplement à Authenticated, sans la réenregistrer par username.
		sto_session.SessionsUser.SetStatus(duckysession.SessionID, sessionmgr.SessionAuthenticated)

		message = "02_12\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" +
			"vaultaire\n" +
			storage.Computeur_ID + "\n" +
			getlocalinformation.GetAllLocalInfForServeur() + "\n" +
			strings.Join(activeSession, ",")

	}

	return message
}
