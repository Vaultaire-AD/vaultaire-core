package tramesmanager

import (
	"fmt"
	"strings"
	keydecodeencode "vaultaire_client/duckynetworkClient/key_encode_decode"
	keymanagement "vaultaire_client/duckynetworkClient/keymanagement"
	"vaultaire_client/logs"
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

func MessageReader(duckysession *storage.DuckySession, reconstructedMessageSize int) {
	messageBuf := make([]byte, reconstructedMessageSize)
	_, err := duckysession.Conn.Read(messageBuf)
	if err != nil {
		fmt.Println("Erreur lors de la lecture du message :", err)
		return
	}

	var messageDecrypt string

	if duckysession.IsSafe {
		// Déchiffrement symétrique AES-GCM
		messageDecrypt, err = keydecodeencode.DecryptAESGCMString(duckysession.SessionKey, messageBuf)
		if err != nil {
			fmt.Println("Erreur lors du déchiffrement symétrique :", err)
			return
		}
	} else {
		// Déchiffrement asymétrique RSA
		privateKeyStr := keymanagement.Get_Client_Private_Key()
		messageDecrypt, err = keydecodeencode.DecryptMessageWithPrivate(privateKeyStr, messageBuf)
		if err != nil {
			fmt.Println("Erreur lors du déchiffrement RSA :", err)
			return
		}
	}

	// Traitement des trames
	logs.Write_Log("DEBUG", messageDecrypt)
	logs.Write_Log("DEBUG", string(duckysession.SessionKey))
	trames_content := parseTrames(messageDecrypt)
	Split_Action(trames_content, duckysession)
}
