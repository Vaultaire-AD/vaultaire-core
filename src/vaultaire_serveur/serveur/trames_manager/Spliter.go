package tramesmanager

import (
	"DUCKY/serveur/authentification/client"
	auts "DUCKY/serveur/authentification/serveur"
	"DUCKY/serveur/database/sync"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/sendmessage"
	"DUCKY/serveur/storage"
	"net"
	"strings"
)

func Split_Action(trames_content storage.Trames_struct_client, conn net.Conn) {
	service := strings.Split(trames_content.Message_Order[0], "_")
	message := ""
	//println(trames_content.Message_Order[0]+"_"+trames_content.Message_Order[1])
	messageOrder := strings.Join(trames_content.Message_Order, "_")
	err := sync.UpdateConnectionTrame(trames_content.SessionIntegritykey, messageOrder)

	if err != nil && messageOrder != "01_01" {
		logs.Write_Log("ERROR", "Error during the update of the connection: "+err.Error())
		conn.Close()
	} else {
		switch service[0] {
		case "01":
			message = auts.Serveur_Auth_Manager(trames_content, conn)
		case "02":
			message = client.Client_Auth_Manager(trames_content, conn)
		default:
			print("FEUR")
		}
		if message == "" {

		} else {
			err := sendmessage.SendMessage(message, trames_content.ClientSoftwareID, conn)
			if err != nil {
				logs.Write_Log("ERROR", "Error sending message: "+err.Error())
			}
		}
	}
}
