package client

import (
	getinformation "vaultaire/serveur/ducky-network/ducky_tools"
	gpomanager "vaultaire/serveur/ducky-network/gpo_manager"
	"vaultaire/serveur/storage"
)

// Client_Auth_Manager manages the authentication requests from clients.
// It processes different message types based on the second element of the Message_Order slice.
// It handles authentication requests, checks authentication status, closes sessions, and retrieves server software information.
// It returns a string message indicating the result of the operation.
func Client_Auth_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "01":
		duckysession.IsSafe = true
		message = SendAuthRequest(trames_content)
	case "03":
		message = CheckAuth(trames_content, duckysession)
	case "05":
		message = closeSession(trames_content)
	case "12":
		getinformation.GetSoftwareServeurInformation(trames_content)
	case "15":
		message = gpomanager.GPO_Manager(trames_content, duckysession)
	}
	return message
}
