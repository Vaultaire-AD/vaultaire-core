package client

import (
	getinformation "DUCKY/serveur/ducky-network/ducky_tools"
	gpomanager "DUCKY/serveur/ducky-network/gpo_manager"
	"DUCKY/serveur/storage"
	"net"
)

// Client_Auth_Manager manages the authentication requests from clients.
// It processes different message types based on the second element of the Message_Order slice.
// It handles authentication requests, checks authentication status, closes sessions, and retrieves server software information.
// It returns a string message indicating the result of the operation.
func Client_Auth_Manager(trames_content storage.Trames_struct_client, conn net.Conn) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "01":
		message = SendAuthRequest(trames_content)
	case "03":
		message = CheckAuth(trames_content, conn)
	case "05":
		message = closeSession(trames_content)
	case "12":
		getinformation.GetSoftwareServeurInformation(trames_content)
	case "15":
		message = gpomanager.GPO_Manager(trames_content, conn)
	}
	return message
}
