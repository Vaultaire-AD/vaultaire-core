package serveurauth

import (
	"fmt"
	"strings"
	"vaultaire_client/duckynetworkClient/sendmessage"
	br "vaultaire_client/duckynetworkClient/trames_manager"
	"vaultaire_client/logs"
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
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la fermeture du fichier: %v", err))
			}
		}()
		logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de l'envoi du message : %v", err))
		return false
	}

	for {
		headerSize := br.Read_Header_Size(duckysession.Conn)
		if headerSize != 0 {
			messagesize := br.Read_Message_Size(duckysession.Conn, headerSize)
			messageBuf := make([]byte, messagesize)
			_, err := duckysession.Conn.Read(messageBuf)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du message : %v", err))
			}
			lines := strings.Split(string(messageBuf), "\n")
			if lines[0] == "getkey" {
				err := WriteToFile(strings.Join(lines[1:], "\n"))
				if err != nil {
					logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de l'écriture du fichier : %v", err))
				}
				return true
			}

		}
	}

}
