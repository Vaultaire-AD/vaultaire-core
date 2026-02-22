package serveurcommunication

import (
	"fmt"
	br "vaultaire_client/duckynetworkClient/trames_manager"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
)

func handleConnection(user string, duckysession *storage.DuckySession) {
	storeConnection(user, *duckysession)
	defer func() {
		if err := duckysession.Conn.Close(); err != nil {
			// Handle or log the error
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
		}
	}()

	for {
		headerSize := br.Read_Header_Size(duckysession.Conn)
		if !storage.ServeurCheck {
			// messagesize := br.ReadMessageSize(conn, headerSize)
			// br.READERforserveurauth(conn, messagesize)
		} else {
			if headerSize != 0 {
				messagesize := br.Read_Message_Size(duckysession.Conn, headerSize)
				br.MessageReader(duckysession, messagesize)
			}
		}
	}
}
