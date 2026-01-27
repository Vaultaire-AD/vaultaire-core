package sendmessage

import (
	"encoding/binary"
	"fmt"
	keyencodedecode "vaultaire_client/duckynetworkClient/key_encode_decode"
	"vaultaire_client/duckynetworkClient/keymanagement"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
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

func SendMessage(message string, duckysession *storage.DuckySession) {
	if message == "" || duckysession.Conn == nil {
		return
	}

	var cipherMsg string
	var err error

	if duckysession.IsSafe {
		// Chiffrement symétrique AES-GCM avec clé de session
		cipherMsg, err = keyencodedecode.EncryptAESGCMString(duckysession.SessionKey, message)
		if err != nil {
			fmt.Println("Erreur lors du chiffrement symétrique :", err)
			return
		}
	} else {
		// Chiffrement asymétrique RSA avec clé publique du serveur
		cipherBytes, err := keyencodedecode.EncryptMessageWithPublic(keymanagement.GetServeurPublicKey(), message)
		if err != nil {
			fmt.Println("Erreur lors du chiffrement asymétrique :", err)
			return
		}
		cipherMsg = string(cipherBytes) // ou Base64 si nécessaire
	}

	// Préparer header et taille du message
	messageSize := CompileMessageSize([]byte(cipherMsg))
	headerSize := []byte{CompileHeaderSize(messageSize)}
	data := append(append(headerSize, messageSize...), []byte(cipherMsg)...)

	// Envoi sur la connexion
	if _, err := duckysession.Conn.Write(data); err != nil {
		defer func() {
			if cerr := duckysession.Conn.Close(); cerr != nil {
				fmt.Printf("Erreur lors de la fermeture de la connexion : %v\n", cerr)
			}
		}()
		fmt.Println("Erreur lors de l'envoi du message :", err)
		return
	}
	logs.Write_Log("DEBUG", string(cipherMsg))
	fmt.Println("Message envoyé avec succès à", duckysession.Conn.RemoteAddr())
}
