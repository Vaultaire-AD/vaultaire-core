package tramesmanager

import (
	"strings"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	keydecodeencode "vaultaire/ducky-network/key_decode_encode"
	keymanagement "vaultaire/ducky-network/key_management"
	"vaultaire/ducky-network/sendmessage"
)

func parseTrames(trames string) storage.Trames_struct_client {
	lines := strings.Split(trames, "\n")

	// SÉCURITÉ : Vérifier qu'on a au moins le minimum vital (5 lignes pour atteindre l'index 4)
	if len(lines) < 5 {
		logs.Write_Log("ERROR", "Trame incomplète reçue : pas assez de lignes")
		return storage.Trames_struct_client{} // Ou gérer l'erreur autrement
	}

	// Vérifier que nous avons exactement trois lignes
	message := strings.Join(lines[5:], "\n")
	action := strings.Split(lines[0], "_")

	username := lines[3]
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

func MessageReader(duckysession *storage.DuckySession, reconstructedMessageSize int) {
	messageBuf := make([]byte, reconstructedMessageSize)
	_, err := duckysession.Conn.Read(messageBuf)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the read of the message: "+err.Error())
		return
	}
	logs.Write_Log("DEBUG", string(messageBuf))
	//fmt.Println("taille du message recu : ", reconstructedMessageSize)
	if string(messageBuf) == "askkey" {
		data := []byte("getkey\n" +
			keymanagement.GetPublicKey())
		messageSize := sendmessage.CompileMessageSize(data)
		headerSize := []byte{sendmessage.CompileHeaderSize(messageSize)}
		datatosend := append(append(headerSize, messageSize...), data...)
		if _, err := duckysession.Conn.Write(datatosend); err != nil {
			err := duckysession.Conn.Close()
			if err != nil {
				logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
			}
			logs.Write_Log("ERROR", "Error during the send of the message: "+err.Error())
			return
		}
		return
	}
	privateKeyStr := keymanagement.GetPrivateKey()
	var messageDecrypt string

	if duckysession.IsSafe {
		// Déchiffrement symétrique
		messageDecrypt, err = keydecodeencode.DecryptAESGCMString(duckysession.SessionKey, messageBuf)
		if err != nil {
			logs.Write_Log("ERROR", "Error during symmetric decryption: "+err.Error())
			return
		}
	} else {
		// Déchiffrement asymétrique RSA
		messageDecrypt, err = keydecodeencode.DecryptMessageWithPrivate(privateKeyStr, messageBuf)
		if err != nil {
			logs.Write_Log("ERROR", "Error during asymmetric decryption: "+err.Error())
			return
		}
	}
	var trames_content = parseTrames(messageDecrypt)
	Split_Action(trames_content, duckysession)
}
