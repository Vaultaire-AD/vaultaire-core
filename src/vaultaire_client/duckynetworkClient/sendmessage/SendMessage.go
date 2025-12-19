package sendmessage

import (
	"encoding/binary"
	"fmt"
	"net"
	keyencodedecode "vaultaire_client/duckynetworkClient/key_encode_decode"
	"vaultaire_client/duckynetworkClient/keymanagement"
)

func CompileMessageSize(message []byte) []byte {
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, uint16(len(message)))

	return sizeBytes
}

func CompileHeaderSize(messageSize []byte) byte {
	headerSize := byte(len(messageSize))
	return headerSize
}

func SendMessage(message string, conn net.Conn) {
	if message == "" || conn == nil {
		return
	}
	cipher_msg, err := keyencodedecode.EncryptMessageWithPublic(keymanagement.GetServeurPublicKey(), message)
	if err != nil {
		fmt.Println("Erreur de chiffrement lors de l'envoie de données" + err.Error())
	}
	messageSize := CompileMessageSize(cipher_msg)
	headerSize := []byte{CompileHeaderSize(messageSize)}
	data := append(append(headerSize, messageSize...), cipher_msg...)
	if _, err := conn.Write(data); err != nil {
		defer func() {
			if err := conn.Close(); err != nil {
				// Handle or log the error
				fmt.Printf("erreur lors de la fermeture du fichier: %v", err)
			}
		}()

		fmt.Println("Erreur lors de l'envoi du message :", err)
		return
	}
	fmt.Println("Message send with succces to", conn.RemoteAddr())
}
