package tramesmanager

import (
	"fmt"
	"strings"
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/duckynetworkClient/userauth"
	"vaultaire_client/duckynetworkClient/userauth/sshauth"
	"vaultaire_client/storage"
)

func Split_Action(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) {
	service := strings.Split(trames_content.Message_Order[0], "_")
	message := ""
	// trames_content.Username = storage.Username
	println(trames_content.Message_Order[0] + "_" + trames_content.Message_Order[1])
	switch service[0] {
	case "02":
		message = userauth.User_Auth_Manager(trames_content, duckysession)
	case "03":
		fmt.Println("SSH Client Manager")
		message = sshauth.SSH_Auth_Manager(trames_content, duckysession.Conn)
		//message = sshclient.SSH_Client_Manager(trames_content, conn)
	default:
		fmt.Println(trames_content.Content)

	}
	sendmessage.SendMessage(message, duckysession)
}
