package tramesmanager

import (
	"fmt"
	"net"
	"strings"
	"vaultaire_client/sendmessage"
	"vaultaire_client/storage"
	"vaultaire_client/userauth"
)

func Split_Action(trames_content storage.Trames_struct_client, conn net.Conn) {
	service := strings.Split(trames_content.Message_Order[0], "_")
	message := ""
	trames_content.Username = storage.Username
	println(trames_content.Message_Order[0] + "_" + trames_content.Message_Order[1])
	switch service[0] {
	case "02":
		message = userauth.User_Auth_Manager(trames_content)
	default:
		fmt.Println(trames_content.Content)
		break
	}
	sendmessage.SendMessage(message, conn)
}
