package tramesmanager

import (
	"strings"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	autc "vaultaire/ducky-network/authentification/client"
	auts "vaultaire/ducky-network/authentification/serveur"
	autssh "vaultaire/ducky-network/authentification/ssh"
	"vaultaire/ducky-network/sendmessage"
	sync "vaultaire/ducky-network/sync"
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
		case "04":
			msg, err := hosthandler.HandleHostTrame(database.GetDatabase(), trames_content, duckysession)
			if err != nil {
				logs.Write_Log("ERROR", "host_handler: "+err.Error())
				message = ""
			} else {
				message = msg
			}
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
