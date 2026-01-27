package tramesmanager

import (
	autc "DUCKY/serveur/ducky-network/authentification/client"
	auts "DUCKY/serveur/ducky-network/authentification/serveur"
	autssh "DUCKY/serveur/ducky-network/authentification/ssh"
	"DUCKY/serveur/ducky-network/sendmessage"
	sync "DUCKY/serveur/ducky-network/sync"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"strings"
)

func Split_Action(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) {
	service := strings.Split(trames_content.Message_Order[0], "_")
	message := ""
	//println(trames_content.Message_Order[0]+"_"+trames_content.Message_Order[1])
	messageOrder := strings.Join(trames_content.Message_Order, "_")
	err := sync.UpdateConnectionTrame(trames_content.SessionIntegritykey, messageOrder)

	if err != nil && messageOrder != "01_01" {
		logs.Write_Log("ERROR", "Error during the update of the connection: "+err.Error())
		err := duckysession.Conn.Close()
		if err != nil {
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	} else {
		switch service[0] {
		case "01":
			message = auts.Serveur_Auth_Manager(trames_content, duckysession)
		case "02":
			message = autc.Client_Auth_Manager(trames_content, duckysession)
		case "03":
			message = autssh.SSH_Client_Manager(trames_content, duckysession)
		default:
			print("FEUR")
		}
		if message == "" {

		} else {
			err := sendmessage.SendMessage(message, trames_content.ClientSoftwareID, duckysession)
			if err != nil {
				logs.Write_Log("ERROR", "Error sending message: "+err.Error())
			}
		}
	}
}
