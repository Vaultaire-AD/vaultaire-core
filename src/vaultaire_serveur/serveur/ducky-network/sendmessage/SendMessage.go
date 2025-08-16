package sendmessage

import (
	keydecodeencode "DUCKY/serveur/ducky-network/key_decode_encode"
	"DUCKY/serveur/logs"
	"encoding/binary"
	"fmt"
	"net"
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

func SendMessage(message string, clientSoftwareID string, conn net.Conn) error {
	if conn == nil {
		logs.Write_Log("ERROR", "Connection is nil")
		return fmt.Errorf("connection is nil")
	}

	cipher_msg, err := keydecodeencode.EncryptMessageWithClientPublic(message, clientSoftwareID)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the encryption: "+err.Error())
		return err
	}
	messageSize := CompileMessageSize(cipher_msg)
	headerSize := []byte{CompileHeaderSize(messageSize)}
	data := append(append(headerSize, messageSize...), cipher_msg...)
	if _, err := conn.Write(data); err != nil {
		defer func() {
			if err := conn.Close(); err != nil {
				// Handle or log the error
				logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
			}
		}()
		logs.Write_Log("ERROR", "Error during the send of the message: "+err.Error())
		return err
	}
	return nil
	//fmt.Println("Message send with succces to", conn.RemoteAddr())
}
