package serveurauth

import (
	"fmt"
	"net"
	"strings"
	"vaultaire_client/sendmessage"
	br "vaultaire_client/trames_manager"
)

func AskServerKey(conn net.Conn) bool {
	message := []byte("askkey")
	fmt.Println("je veux une clé serveur")
	messageSize := sendmessage.CompileMessageSize(message)
	headerSize := []byte{sendmessage.CompileHeaderSize(messageSize)}
	data := append(append(headerSize, messageSize...), message...)
	if _, err := conn.Write(data); err != nil {
		conn.Close()
		fmt.Println("Erreur lors de l'envoi du message :", err)
		return false
	}
	fmt.Println("Message send with succces to", conn.RemoteAddr())
	for {
		headerSize := br.Read_Header_Size(conn)
		if headerSize != 0 {
			messagesize := br.Read_Message_Size(conn, headerSize)
			fmt.Println("\nYou receive a message from : ", conn.RemoteAddr())
			messageBuf := make([]byte, messagesize)
			_, err := conn.Read(messageBuf)
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
