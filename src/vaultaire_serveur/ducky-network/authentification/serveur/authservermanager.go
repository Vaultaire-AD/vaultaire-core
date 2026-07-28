package serveur

import (
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/sessionmgr"
	sync "vaultaire/ducky-network/sync"
)

// Serveur_Auth_Manager manages the authentication requests from servers.
// It processes different message types based on the second element of the Message_Order slice.
// It handles authentication requests and returns a string message indicating the result of the operation.
// This function is part of the server authentication management system and is used to maintain session integrity and security.
// It is called when a server requests authentication, ensuring that the server is properly authenticated and logged.
func Serveur_Auth_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "01":
		oldSessionID := duckysession.SessionID

		sessionIntegritykey, err := sync.AddConnectionToMap("01_01", trames_content.ClientSoftwareID)
		if err != nil {
			message = "error"
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone,
				"Error during initial handshake: "+err.Error(), logs.WithMeta(oldSessionID, trames_content.Username))
			err := duckysession.Conn.Close()
			if err != nil {
				logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
			}
			break
		}
		duckysession.SessionKey = []byte(sessionIntegritykey)

		// À partir d'ici, SessionID = SessionIntegritykey réel : le même
		// identifiant sert de clé de log et de clé réseau (voir
		// sessionmgr.Manager.Rekey). On attache aussi l'identité annoncée par
		// le client (pas encore prouvée, mais utile pour tracer une tentative
		// même si elle échoue plus loin dans le login).
		duckysession.SessionID = sessionIntegritykey
		sessionmgr.Sessions.Rekey(oldSessionID, sessionIntegritykey)
		sessionmgr.Sessions.SetIdentity(sessionIntegritykey, trames_content.Username, trames_content.ClientSoftwareID)

		message = Prove_Identity(trames_content.Content, sessionIntegritykey)
	}
	return message
}
