package gpomanager

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/sendmessage"
	"DUCKY/serveur/tools"
	"net"
	"strings"
)

func SendGPOtoClientByUsername(username string, conn net.Conn, clientsoftware string, session_key_integrity string) (string, error) {
	db := database.GetDatabase()
	clientOS, err := database.GetClientOS(db, clientsoftware)
	if err != nil {
		return "", err
	}
	clientOS = tools.DetectOSName(clientOS)
	groupName, err := database.GetUserGroupNameWhenLogin(db, username, clientsoftware)
	if err != nil {
		return "", err
	}
	commands, err := database.GET_GPOcommandByOSandGroup(db, groupName, clientOS)
	if err != nil {
		return "", err
	}
	commands_string := strings.Join(commands, "\n")
	err = sendmessage.SendMessage("02_06\nserveur_central\n"+session_key_integrity+"\n"+commands_string, clientsoftware, conn)
	if err != nil {
		return "", err
	}
	return "GPO sent successfully", nil
}

// TODO : Send GPO to client
