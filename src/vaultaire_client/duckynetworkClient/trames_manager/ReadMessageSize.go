package tramesmanager

import (
	"encoding/binary"
	"fmt"
	"net"
)

func Read_Message_Size(conn net.Conn, headerSize int) int {
	messageSizeBuf := make([]byte, 2)

	_, err := conn.Read(messageSizeBuf)
	if err != nil {
		fmt.Println("Erreur lors de la lecture de messageSize :", err)
		return 0
	}
	size := int(binary.BigEndian.Uint16(messageSizeBuf))
	return size

}
