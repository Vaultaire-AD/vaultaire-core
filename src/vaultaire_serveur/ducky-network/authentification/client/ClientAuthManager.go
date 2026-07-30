package client

import (
	"vaultaire/core/storage"
	getinformation "vaultaire/ducky-network/ducky_tools"
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
		closeSession(trames_content, duckysession)
	case "12":
		getinformation.GetSoftwareServeurInformation(trames_content)
	}
	// Le transport des GPO a quitté la catégorie 02 : il a désormais sa propre
	// catégorie 05 (voir Tableau_Protocole_Réseau.md). L'ancien couple 02_15/02_16
	// envoyait une liste de commandes shell, ce que le modèle déclaratif remplace.
	return message
}
