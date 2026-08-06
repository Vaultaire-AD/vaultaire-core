package tramesmanager

import (
	"net"
)

func Read_Header_Size(conn net.Conn) (int, error) { // Ajoute error ici
	headerSizeBuf := make([]byte, 1)
	_, err := conn.Read(headerSizeBuf)
	if err != nil {
		return 0, err // On renvoie la vraie erreur (EOF, timeout, etc.)
	}
	return int(headerSizeBuf[0]), nil
}
