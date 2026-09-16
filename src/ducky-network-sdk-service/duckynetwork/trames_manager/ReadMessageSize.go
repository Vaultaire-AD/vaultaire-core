package tramesmanager

import (
	"encoding/binary"
	"net"
)

func Read_Message_Size(conn net.Conn, headerSize int) (int, error) {
	messageSizeBuf := make([]byte, 2)
	_, err := conn.Read(messageSizeBuf)
	if err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(messageSizeBuf))
	return size, nil
}
