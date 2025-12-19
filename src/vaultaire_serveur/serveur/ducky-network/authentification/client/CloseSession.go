package client

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
)

// closeSession handles the closing of a session for a client.
// It deletes the session from the database and logs the action.
// It returns a string message indicating the result of the operation.
// The message format is "02_06\nserveur_central\n<session_integrity_key>\n : Session Delete".
// The session_integrity_key is used to verify the integrity of the session being closed.
// This function is called when a client requests to close their session.
// It takes a Trames_struct_client as input, which contains the username and client software ID.
// The function deletes the session from the database and logs the action.
// It returns a formatted string indicating the success of the operation.
// The returned string includes the session integrity key for verification purposes.
// It is important to ensure that the session integrity key is valid and corresponds to the session being closed.
// This function is part of the client authentication management system and is used to maintain session integrity and security.
// It is called when a client wants to terminate their session, ensuring that the session is properly closed and logged.
// It is essential for maintaining the security and integrity of the client-server communication.
func closeSession(trames_content storage.Trames_struct_client) string {
	err := database.DeleteDidLogin(database.DB, trames_content.Username, trames_content.ClientSoftwareID)
	if err != nil {
		logs.Write_Log("ERROR", "Error deleting session for "+trames_content.Username+" from Computeur "+trames_content.ClientSoftwareID+": "+err.Error())
		return "02_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\n : Error deleting session"
	}
	DeleteAuthByID(trames_content.ClientSoftwareID)
	logs.Write_Log("INFO", "Session closed for "+trames_content.Username+" from Computeur "+trames_content.ClientSoftwareID)
	return "02_06\nserveur_central\n" + trames_content.SessionIntegritykey + "\n : Session Delete"
}
