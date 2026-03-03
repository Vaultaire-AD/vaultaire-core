package sendmessage

import (
	keydecodeencode "vaultaire/serveur/ducky-network/key_decode_encode"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"encoding/binary"
	"fmt"
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

func SendMessage(message string, clientSoftwareID string, duckysession *storage.DuckySession) error {
	if duckysession.Conn == nil {
		logs.Write_Log("ERROR", "Connection is nil")
		return fmt.Errorf("connection is nil")
	}

	var cipherMsg string
	var err error

	if duckysession.IsSafe {
		// Chiffrement symétrique AES-GCM
		cipherMsg, err = keydecodeencode.EncryptAESGCMString(duckysession.SessionKey, message)
		if err != nil {
			logs.Write_Log("ERROR", "Error during symmetric encryption: "+err.Error())
			return err
		}
	} else {
		// Chiffrement asymétrique RSA
		cipherBytes, err := keydecodeencode.EncryptMessageWithClientPublic(message, clientSoftwareID)
		if err != nil {
			logs.Write_Log("ERROR", "Error during asymmetric encryption: "+err.Error())
			return err
		}
		cipherMsg = string(cipherBytes)
	}

	// Prépare le header et la taille du message
	messageSize := CompileMessageSize([]byte(cipherMsg))
	headerSize := []byte{CompileHeaderSize(messageSize)}
	data := append(append(headerSize, messageSize...), []byte(cipherMsg)...)

	// Envoi du message
	if _, err := duckysession.Conn.Write(data); err != nil {
		defer func() {
			if cerr := duckysession.Conn.Close(); cerr != nil {
				logs.Write_Log("ERROR", "Error closing connection: "+cerr.Error())
			}
		}()
		logs.Write_Log("ERROR", "Error sending message: "+err.Error())
		return err
	}

	return nil
}
