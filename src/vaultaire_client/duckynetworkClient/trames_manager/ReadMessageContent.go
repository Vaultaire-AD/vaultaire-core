package tramesmanager

import (
	"fmt"
	"net"
	"strings"
	keydecodeencode "vaultaire_client/duckynetworkClient/key_encode_decode"
	keymanagement "vaultaire_client/duckynetworkClient/keymanagement"
	"vaultaire_client/storage"
)

func parseTrames(trames string) storage.Trames_struct_client {
	lines := strings.Split(trames, "\n")

	// Vérifier que nous avons exactement trois lignes
	message := strings.Join(lines[3:], "\n")
	action := strings.Split(lines[0], "_")

	return storage.Trames_struct_client{
		Message_Order:       action,
		Destination_Server:  lines[1],
		SessionIntegritykey: lines[2],
		Username:            "",
		Content:             message,
	}
}

var log = false

func VarLog() bool {
	return log
}

func MessageReader(conn net.Conn, reconstructedMessageSize int) {
	messageBuf := make([]byte, reconstructedMessageSize)
	_, err := conn.Read(messageBuf)
	if err != nil {
		fmt.Println("Erreur lors de la lecture du message :", err)
	}
	// fmt.Println("taille du message recu : ", reconstructedMessageSize)

	privateKeyStr := keymanagement.Get_Client_Private_Key()
	messageDecrypt, err := keydecodeencode.DecryptMessageWithPrivate(privateKeyStr, messageBuf)
	if err != nil {
		fmt.Println("Erreur lors du dechifrement :", err)
	}
	var trames_content = parseTrames(messageDecrypt)
	Split_Action(trames_content, conn)
}
