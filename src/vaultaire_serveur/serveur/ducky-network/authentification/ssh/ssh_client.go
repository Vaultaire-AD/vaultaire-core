package sshclient

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"strings"
)

func SSH_Client_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "01":
		message = SSH_SEND_Pubkey(trames_content)
	default:
	}
	return message
}

func SSH_SEND_Pubkey(trames_content storage.Trames_struct_client) string {
	content := strings.Split(trames_content.Content, "\n")
	if len(content) < 2 {
		logs.Write_Log("ERROR", "Malformed SSH pubkey request")
		return "02_07\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\ninvalid request"
	}

	order := content[0]
	sshUser := content[1]

	can, err := database.DidUserCanLogin(
		database.GetDatabase(),
		sshUser,
		trames_content.ClientSoftwareID,
	)
	if err != nil {
		logs.Write_Log("ERROR", sshUser+" try to login by ssh but error for get user can login")
		return "02_07\nSomething go wrong contact your administrator for ssh connection"
	}

	if can {
		if order == "ask_sshpubkey" {
			userid, err := database.Get_User_ID_By_Username(
				database.GetDatabase(),
				sshUser,
			)
			if err != nil {
				logs.Write_Log(
					"ERROR",
					"Erreur récupération ID utilisateur "+sshUser+" : "+err.Error(),
				)
				return "03_03\nserveur_central\n" +
					trames_content.SessionIntegritykey + "\n" +
					sshUser + "\nuser ID error"
			}

			pubkeys, err := database.Get_PublicKeys_ByUserID(
				database.GetDatabase(),
				userid,
			)
			if err != nil {
				logs.Write_Log(
					"ERROR",
					"Erreur récupération clés SSH "+sshUser+" : "+err.Error(),
				)
				return "03_03\nserveur_central\n" +
					trames_content.SessionIntegritykey + "\n" +
					sshUser + "\ndatabase retrieve pubkey error"
			}

			pubkeyStr := strings.Join(pubkeys, "\n")

			return "03_02\nserveur_central\n" +
				trames_content.SessionIntegritykey + "\n" +
				sshUser + "\n" +
				pubkeyStr
		}
	}

	logs.Write_Log(
		"WARNING",
		sshUser+" Does not have the permission for SSH login to "+trames_content.ClientSoftwareID,
	)

	return "02_07\nserveur_central\n" +
		trames_content.SessionIntegritykey +
		"\nYou are not authentificate for SSH"
}
