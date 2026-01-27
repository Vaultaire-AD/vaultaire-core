package serveurauth

import (
	"fmt"
	"strings"
	"vaultaire_client/duckynetworkClient/sendmessage"
	br "vaultaire_client/duckynetworkClient/trames_manager"
	"vaultaire_client/storage"
)

func AskServerKey(duckysession *storage.DuckySession) bool {
	message := []byte("askkey")
	fmt.Println("je veux une clé serveur")
	messageSize := sendmessage.CompileMessageSize(message)
	headerSize := []byte{sendmessage.CompileHeaderSize(messageSize)}
	data := append(append(headerSize, messageSize...), message...)
	if _, err := duckysession.Conn.Write(data); err != nil {
		defer func() {
			if err := duckysession.Conn.Close(); err != nil {
				// Handle or log the error
				fmt.Printf("erreur lors de la fermeture du fichier: %v", err)
			}
		}()

		fmt.Println("Erreur lors de l'envoi du message :", err)
		return false
	}
	fmt.Println("Message send with succces to", duckysession.Conn.RemoteAddr())
	for {
		headerSize := br.Read_Header_Size(duckysession.Conn)
		if headerSize != 0 {
			messagesize := br.Read_Message_Size(duckysession.Conn, headerSize)
			fmt.Println("\nYou receive a message from : ", duckysession.Conn.RemoteAddr())
			messageBuf := make([]byte, messagesize)
			_, err := duckysession.Conn.Read(messageBuf)
			if err != nil {
				fmt.Println("Erreur lors de la lecture du message :", err)
			}
			lines := strings.Split(string(messageBuf), "\n")
			fmt.Println(lines[0])
			if lines[0] == "getkey" {
				fmt.Println(strings.Join(lines[1:], ""))
				err := WriteToFile(strings.Join(lines[1:], "\n"))
				if err != nil {
					fmt.Println("Erreur :", err)
				}
				return true
			}

		}
	}

}
