package userauth

import (
	"duckynetworkclient/V1/duckynetwork/ducky_tool/getlocalinformation"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	"duckynetworkclient/V1/sessionmgr"
	"fmt"
	"strings"
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
		stosession.SessionsUser.SetStatus(duckysession.SessionID, sessionmgr.SessionAuthenticated)
		stosession.SessionsUser.Touch(duckysession.SessionID)
		activeSession, _ := getlocalinformation.GetActiveUsers()

		message = "02_12\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" +
			username + "\n" +
			storage.Computeur_ID + "\n" +
			getlocalinformation.GetAllLocalInfForServeur() + "\n" +
			strings.Join(activeSession, ",")

	// Le transport des GPO a quitté la catégorie 02 : il a désormais sa propre
	// catégorie 05 (voir Tableau_Protocole_Réseau.md). L'ancien 02_16 recevait
	// une liste de commandes shell exécutées telles quelles, ce que le modèle
	// déclaratif remplace entièrement.

	case "07":
		lines := strings.Split(trames_content.Content, "\n")
		logs.Write_log("WARNING",
			fmt.Sprintf("Authentification failed for user %s : %s", lines[0], lines[1]))

	case "11":
		// lines := strings.Split(trames_content.Content, "\n")
		// username := lines[0]
		activeSession, _ := getlocalinformation.GetActiveUsers()

		// logs.Write_log("INFO", fmt.Sprintf("%s en ligne (session id=%s)", username, duckysession.SessionID))

		// La session vaultaire a déjà été enregistrée (Pending) sous
		// MotherSessionID dès l'ouverture de la connexion ; on la passe
		// simplement à Authenticated, sans la réenregistrer par username.
		stosession.SessionsUser.SetStatus(duckysession.SessionID, sessionmgr.SessionAuthenticated)

		message = "02_12\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" +
			"vaultaire\n" +
			storage.Computeur_ID + "\n" +
			getlocalinformation.GetAllLocalInfForServeur() + "\n" +
			strings.Join(activeSession, ",")

	}

	return message
}
