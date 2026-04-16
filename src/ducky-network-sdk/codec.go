package duckynetwork

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func writePacket(conn net.Conn, payload []byte) error {
	if conn == nil {
		return fmt.Errorf("connection nil")
	}
	sizeBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBuf, uint16(len(payload)))
	data := append([]byte{byte(len(sizeBuf))}, sizeBuf...)
	data = append(data, payload...)
	_, err := conn.Write(data)
	return err
}

func readPacket(conn net.Conn) ([]byte, error) {
	if conn == nil {
		return nil, fmt.Errorf("connection nil")
	}
	headerSize := make([]byte, 1)
	if _, err := io.ReadFull(conn, headerSize); err != nil {
		return nil, err
	}
	sizeBuf := make([]byte, int(headerSize[0]))
	if _, err := io.ReadFull(conn, sizeBuf); err != nil {
		return nil, err
	}
	if len(sizeBuf) != 2 {
		return nil, fmt.Errorf("header size unsupported: %d", len(sizeBuf))
	}
	msgLen := binary.BigEndian.Uint16(sizeBuf)
	payload := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
