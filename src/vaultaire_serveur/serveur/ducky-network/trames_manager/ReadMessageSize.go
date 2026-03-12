package tramesmanager

import (
	"vaultaire/serveur/logs"
	"encoding/binary"
	"net"
)

func Read_Message_Size(conn net.Conn, headerSize int) int {
	messageSizeBuf := make([]byte, headerSize)

	_, err := conn.Read(messageSizeBuf)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the read of the message size: "+err.Error())
		return 0
	}
	size := int(binary.BigEndian.Uint16(messageSizeBuf))
	return size

}
