package tramesmanager

import (
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/userauth"
	"fmt"
	"strings"
)

func Split_Action(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) {
	service := strings.Split(trames_content.Message_Order[0], "_")
	message := ""
	// trames_content.Username = storage.Username
	// logs.Print_Log(trames_content.Message_Order[0] + "_" + trames_content.Message_Order[1])
	switch service[0] {
	case "02":
		message = userauth.User_Auth_Manager(trames_content, duckysession)
	default:
		fmt.Println(trames_content.Content)

	}
	sendmessage.SendMessage(message, duckysession)
}
