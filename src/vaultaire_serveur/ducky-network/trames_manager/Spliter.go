package tramesmanager

import (
	"fmt"
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	autc "vaultaire/ducky-network/authentification/client"
	auts "vaultaire/ducky-network/authentification/serveur"
	autssh "vaultaire/ducky-network/authentification/ssh"
	gpomanager "vaultaire/ducky-network/gpo_manager"
	hosthandler "vaultaire/ducky-network/host_handler"
	revocationmanager "vaultaire/ducky-network/revocation_manager"
	"vaultaire/ducky-network/sendmessage"
	"vaultaire/ducky-network/sessionmgr"
)

// clientMatchesSession compare la machine annoncée par une trame à celle figée
// pour la connexion.
//
// Tant que la poignée de main 01_01 n'a pas eu lieu, aucune machine n'est encore
// liée : c'est justement la trame qui l'établit, et la refuser empêcherait toute
// connexion. On laisse donc passer, la trame 01_01 étant de toute façon la seule
// acceptée à ce stade par le contrôle d'ordre.
func clientMatchesSession(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) bool {
	if duckysession == nil || duckysession.BoundClientSoftwareID == "" {
		return true
	}
	return trames_content.ClientSoftwareID == duckysession.BoundClientSoftwareID
}

func Split_Action(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) {
	service := strings.Split(trames_content.Message_Order[0], "_")
	message := ""
	//println(trames_content.Message_Order[0]+"_"+trames_content.Message_Order[1])
	messageOrder := strings.Join(trames_content.Message_Order, "_")

	// La machine est figée à la poignée de main 01_01 et ne peut plus changer.
	//
	// Sans ce contrôle, chaque handler prenait le ClientSoftwareID directement
	// dans la trame : un client authentifié pouvait demander les GPO — règles
	// sudo, configuration SSH, contenu des fichiers déployés — de n'importe
	// quelle autre machine du parc, ou le sel d'un utilisateur via 03_04.
	//
	// Le contrôle est ici plutôt que dans chaque handler : un point unique
	// couvre les catégories 02, 03, 04 et 05, et couvrira aussi celles qui
	// seront ajoutées plus tard sans que personne n'ait à y penser.
	if !clientMatchesSession(trames_content, duckysession) {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"trame %s refusée : la session %s est liée à la machine %q mais la trame annonce %q",
			messageOrder, duckysession.SessionID,
			duckysession.BoundClientSoftwareID, trames_content.ClientSoftwareID))
		if err := duckysession.Conn.Close(); err != nil {
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
		return
	}

	err := sessionmgr.Sessions.UpdateConnectionTrame(trames_content.SessionIntegritykey, messageOrder)

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
		case "05":
			message = gpomanager.GPO_Trame_Manager(trames_content, duckysession)
		case "06":
			message = revocationmanager.Revocation_Trame_Manager(trames_content, duckysession)
		default:
			logs.Write_Log("WARNING", "Unknown service: "+service[0])
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
