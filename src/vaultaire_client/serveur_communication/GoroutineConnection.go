package serveurcommunication

import (
	"fmt"
	"net"
	"vaultaire_client/storage"
	br "vaultaire_client/trames_manager"
)

func handleConnection(user string, conn net.Conn) {
	storeConnection(user, conn)
	defer func() {
		if err := conn.Close(); err != nil {
			// Handle or log the error
			fmt.Printf("erreur lors de la fermeture du fichier: %v", err)
		}
	}()

	for {
		headerSize := br.Read_Header_Size(conn)
		if !storage.ServeurCheck {
			// messagesize := br.ReadMessageSize(conn, headerSize)
			// br.READERforserveurauth(conn, messagesize)
		} else {
			if headerSize != 0 {
				messagesize := br.Read_Message_Size(conn, headerSize)
				if !br.VarLog() {
					fmt.Println("\nYou receive a message from : ", conn.RemoteAddr())
					fmt.Println("taille du header recu: ", headerSize)
					fmt.Println("taille du message recu : ", messagesize)
				}
				br.MessageReader(conn, messagesize)
			}
		}
	}
}
