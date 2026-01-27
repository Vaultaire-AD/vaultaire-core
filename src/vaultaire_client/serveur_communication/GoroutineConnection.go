package serveurcommunication

import (
	"fmt"
	br "vaultaire_client/duckynetworkClient/trames_manager"
	"vaultaire_client/storage"
)

func handleConnection(user string, duckysession *storage.DuckySession) {
	storeConnection(user, *duckysession)
	defer func() {
		if err := duckysession.Conn.Close(); err != nil {
			// Handle or log the error
			fmt.Printf("erreur lors de la fermeture du fichier: %v", err)
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
				if !br.VarLog() {
					fmt.Println("\nYou receive a message from : ", duckysession.Conn.RemoteAddr())
					fmt.Println("taille du header recu: ", headerSize)
					fmt.Println("taille du message recu : ", messagesize)
				}
				br.MessageReader(duckysession, messagesize)
			}
		}
	}
}
