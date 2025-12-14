package tramesmanager

import (
	keydecodeencode "DUCKY/serveur/ducky-network/key_decode_encode"
	keymanagement "DUCKY/serveur/ducky-network/key_management"
	"DUCKY/serveur/ducky-network/sendmessage"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"net"
	"strings"
)

func parseTrames(trames string) storage.Trames_struct_client {
	lines := strings.Split(trames, "\n")

	// Vérifier que nous avons exactement trois lignes
	message := strings.Join(lines[5:], "\n")
	action := strings.Split(lines[0], "_")

	username := ""
	domain := ""
	// Si présence de @ → split user@domain
	if strings.Contains(lines[3], "@") {
		parts := strings.SplitN(lines[3], "@", 2)
		username = parts[0]
		domain = parts[1]
	}

	return storage.Trames_struct_client{
		Message_Order:       action,
		Destination_Server:  lines[1],
		SessionIntegritykey: lines[2],
		Username:            username,
		Domain:              domain,
		ClientSoftwareID:    lines[4],
		Content:             message,
	}
}

func MessageReader(conn net.Conn, reconstructedMessageSize int) {
	messageBuf := make([]byte, reconstructedMessageSize)
	_, err := conn.Read(messageBuf)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the read of the message: "+err.Error())
		return
	}
	//fmt.Println("taille du message recu : ", reconstructedMessageSize)
	if string(messageBuf) == "askkey" {
		data := []byte("getkey\n" +
			keymanagement.GetPublicKey())
		messageSize := sendmessage.CompileMessageSize(data)
		headerSize := []byte{sendmessage.CompileHeaderSize(messageSize)}
		datatosend := append(append(headerSize, messageSize...), data...)
		if _, err := conn.Write(datatosend); err != nil {
			err := conn.Close()
			if err != nil {
				logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
			}
			logs.Write_Log("ERROR", "Error during the send of the message: "+err.Error())
			return
		}
		return
	}
	privateKeyStr := keymanagement.GetPrivateKey()
	messageDecrypt, err := keydecodeencode.DecryptMessageWithPrivate(privateKeyStr, messageBuf)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the decryption: "+err.Error())
		return
	}

	var trames_content = parseTrames(messageDecrypt)
	Split_Action(trames_content, conn)
}
