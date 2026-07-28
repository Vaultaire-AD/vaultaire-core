package sendmessage

import (
	"encoding/binary"
	"fmt"
	"strings"
	keyencodedecode "vaultaire_client/duckynetworkClient/key_encode_decode"
	"vaultaire_client/duckynetworkClient/keymanagement"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
)

// Côté client
func BuildClientTrame(action, dest, sessionKey, username, clientID string, contentLines ...string) string {
	parts := []string{action, dest, sessionKey, username, clientID}
	parts = append(parts, contentLines...)
	return strings.Join(parts, "\n")
}

func CompileMessageSize(message []byte) []byte {
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, uint16(len(message)))

	return sizeBytes
}

func CompileHeaderSize(messageSize []byte) byte {
	headerSize := byte(len(messageSize))
	return headerSize
}

func SendMessage(message string, duckysession *storage.DuckySession) {

	// 1. Vérification de sécurité
	if message == "" || duckysession.Conn == nil {
		return
	}

	var cipherMsg string
	var err error

	// 2. chiffrement (AES ou RSA)
	if duckysession.IsSafe {
		// Chiffrement symétrique AES-GCM avec clé de session
		cipherMsg, err = keyencodedecode.EncryptAESGCMString(duckysession.SessionKey, message)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors du chiffrement symétrique : %v", err))
			return
		}
	} else {
		// Chiffrement asymétrique RSA avec clé publique du serveur
		cipherBytes, err := keyencodedecode.EncryptMessageWithPublic(keymanagement.GetServeurPublicKey(), message)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors du chiffrement asymétrique : %v", err))
			return
		}
		cipherMsg = string(cipherBytes) // ou Base64 si nécessaire
	}

	// 3. Préparation du paquet (Header + Size + Payload)
	messageSize := CompileMessageSize([]byte(cipherMsg))
	headerSize := []byte{CompileHeaderSize(messageSize)}

	// Construction de la trame : [1 byte HeaderSize][2 bytes MessageSize][Payload]
	data := append(append(headerSize, messageSize...), []byte(cipherMsg)...)

	// 4. Envoi sur la connexion
	_, err = duckysession.Conn.Write(data)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Échec d'envoi au serveur: %v", err))
		// CRITIQUE : Si l'envoi échoue, on force la fermeture du socket.
		// Cela va débloquer la goroutine handleConnection qui est en train de Read()
		duckysession.Conn.Close()
		return
	}
}
