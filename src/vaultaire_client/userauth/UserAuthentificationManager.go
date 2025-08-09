package userauth

import (
	"fmt"
	"net"
	"strings"
	"vaultaire_client/gpo"
	"vaultaire_client/sendmessage"
	"vaultaire_client/storage"
	"vaultaire_client/tools/getlocalinformation"
)

func AskAuthentification(username string, password string, conn net.Conn, sessionIntegritykey string) {
	message := fmt.Sprintf("02_01\nserveur_central\n%s\n%s\n%s\n%s", sessionIntegritykey, username, storage.Computeur_ID, password)
	sendmessage.SendMessage(message, conn)
}

func User_Auth_Manager(trames_content storage.Trames_struct_client) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "02":
		println("Send Proof of work for identification :", trames_content.Content)
		return "02_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + trames_content.Username + "\n" + storage.Computeur_ID + "\n" + trames_content.Content
	case "04":
		//("02_04\nserveur_central\n" + strconv.FormatBool(admin) + "\nYou are authentificate Has : \n" + username + "\n" + string(key))
		lines := strings.Split(trames_content.Content, "\n")
		content := strings.Join(lines[3:], "\n")
		storage.AES_key = []byte(content)
		fmt.Println(lines[0])
		storage.Authentification_PAM <- "success"
		if lines[0] == "true" {
			storage.IsAdmin = true
		} else {
			storage.IsAdmin = false
		}
		fmt.Println(lines[1] + lines[2])
		activeSession, _ := getlocalinformation.GetActiveUsers()
		message = "02_12\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + trames_content.Username + "\n" + storage.Computeur_ID + "\n" + getlocalinformation.GetAllLocalInfForServeur() + "\n" + strings.Join(activeSession, ",")
	case "06":
		// ("02_06\nserveur_central\n"+session_key_integrity+"\n"+commands_string)
		lines := strings.Split(trames_content.Content, "\n")
		fmt.Println(lines[0])
		for i := 1; i < len(lines); i++ {
			err := gpo.ApplyGPOsAsUser(lines[i], storage.Username)
			if err != nil {
				fmt.Println("Erreur lors de l'application des GPOs :", err)
			}
		}

	case "07":
		lines := strings.Split(trames_content.Content, "\n")
		fmt.Println(lines[0])
		storage.Authentification_PAM <- "failed"
	case "11":
		lines := strings.Split(trames_content.Content, "\n")
		fmt.Println(lines[0])
		activeSession, _ := getlocalinformation.GetActiveUsers()
		message = "02_12\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + "vaultaire" + "\n" + storage.Computeur_ID + "\n" + getlocalinformation.GetAllLocalInfForServeur() + "\n" + strings.Join(activeSession, ",")
	default:
		break
	}

	return message
}
