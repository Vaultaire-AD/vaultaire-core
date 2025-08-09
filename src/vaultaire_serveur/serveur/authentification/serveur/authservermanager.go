package serveur

import (
	"DUCKY/serveur/database/sync"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"net"
)

// Serveur_Auth_Manager manages the authentication requests from servers.
// It processes different message types based on the second element of the Message_Order slice.
// It handles authentication requests and returns a string message indicating the result of the operation.
// This function is part of the server authentication management system and is used to maintain session integrity and security.
// It is called when a server requests authentication, ensuring that the server is properly authenticated and logged.
func Serveur_Auth_Manager(trames_content storage.Trames_struct_client, conn net.Conn) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "01":
		sessionIntegritykey, err := sync.AddConnectionToMap("01_01", trames_content.ClientSoftwareID)
		if err != nil {
			message = "error"
			err := conn.Close()
			if err != nil {
				logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
			}
			break
		}
		message = Prove_Identity(trames_content.Content, sessionIntegritykey)
	}
	return message
}
