package tramesmanager

import (
	keyencodedecode "duckynetworkclient/V1/duckynetwork/key_encode_decode"
	"duckynetworkclient/V1/duckynetwork/keymanagement"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"strings"
)

func ParseTrames(trames string) storage.Trames_struct_client {
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

func MessageReader(duckysession *storage.DuckySession, reconstructedMessageSize int) {
	messageBuf := make([]byte, reconstructedMessageSize)
	_, err := duckysession.Conn.Read(messageBuf)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du message : %v", err))
		return
	}

	var messageDecrypt string

	if duckysession.IsSafe {
		// Déchiffrement symétrique AES-GCM
		messageDecrypt, err = keyencodedecode.DecryptAESGCMString(duckysession.SessionKey, messageBuf)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors du déchiffrement symétrique : %v", err))
			return
		}
	} else {
		// Déchiffrement asymétrique RSA
		privateKeyStr := keymanagement.Get_Client_Private_Key()
		messageDecrypt, err = keyencodedecode.DecryptMessageWithPrivate(privateKeyStr, messageBuf)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors du déchiffrement RSA : %v", err))
			return
		}
	}

	// Traitement des trames
	trames_content := ParseTrames(messageDecrypt)
	Split_Action(trames_content, duckysession)
}
