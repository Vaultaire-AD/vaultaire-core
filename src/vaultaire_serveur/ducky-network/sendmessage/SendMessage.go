package sendmessage

import (
	"encoding/binary"
	"fmt"
	"strings"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	keydecodeencode "vaultaire/ducky-network/key_decode_encode"
)

// Côté serveur
func BuildServerTrame(action, dest, sessionKey string, contentLines ...string) string {
	parts := []string{action, dest, sessionKey}
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

func SendMessage(message string, clientSoftwareID string, duckysession *storage.DuckySession) error {
	meta := logs.WithMeta(duckysession.SessionID, clientSoftwareID)

	if duckysession.Conn == nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Connection is nil", meta)
		return fmt.Errorf("connection is nil")
	}

	var cipherMsg string
	var err error

	if duckysession.IsSafe {
		// Chiffrement symétrique AES-GCM
		cipherMsg, err = keydecodeencode.EncryptAESGCMString(duckysession.SessionKey, message)
		if err != nil {
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error during symmetric encryption: "+err.Error(), meta)
			return err
		}
	} else {
		// Chiffrement asymétrique RSA
		cipherBytes, err := keydecodeencode.EncryptMessageWithClientPublic(message, clientSoftwareID)
		if err != nil {
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error during asymmetric encryption: "+err.Error(), meta)
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
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error sending message: "+err.Error(), meta)
		if cerr := duckysession.Conn.Close(); cerr != nil {
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "Error closing connection: "+cerr.Error(), meta)
		}
		return err
	}

	return nil
}
