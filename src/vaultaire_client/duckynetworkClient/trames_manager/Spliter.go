package tramesmanager

import (
	"fmt"
	"strings"
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/duckynetworkClient/userauth"
	"vaultaire_client/duckynetworkClient/userauth/sshauth"
	"vaultaire_client/gpo"
	"vaultaire_client/revocation"
	"vaultaire_client/storage"
)

func Split_Action(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) {
	service := strings.Split(trames_content.Message_Order[0], "_")
	message := ""
	// trames_content.Username = storage.Username
	// logs.Print_Log(trames_content.Message_Order[0] + "_" + trames_content.Message_Order[1])
	switch service[0] {
	case "02":
		message = userauth.User_Auth_Manager(trames_content, duckysession)
	case "03":
		message = sshauth.SSH_Auth_Manager(trames_content, duckysession.Conn)
		//message = sshclient.SSH_Client_Manager(trames_content, conn)
	case "05":
		// Transport des GPO. Les réponses sont traitées de façon asynchrone :
		// le paquet gpo réveille le cycle en attente et enchaîne lui-même les
		// demandes de fragments, donc rien n'est renvoyé ici.
		if len(trames_content.Message_Order) > 1 {
			gpo.HandleTrame(trames_content.Message_Order[1],
				trames_content.SessionIntegritykey, trames_content.Content)
		}
	case "06":
		// Kill switch. Contrairement aux GPO, la réponse est synchrone : l'agent
		// applique l'ordre puis acquitte immédiatement. Le serveur compte sur
		// cet acquittement pour arrêter de rejouer.
		if len(trames_content.Message_Order) > 1 {
			message = revocation.HandleTrame(trames_content.Message_Order[1],
				trames_content.SessionIntegritykey, trames_content.Content)
		}
	default:
		fmt.Println(trames_content.Content)

	}
	sendmessage.SendMessage(message, duckysession)
}
