package tramesmanager

import (
	"net"
)

func Read_Header_Size(conn net.Conn) int {

	headerSizeBuf := make([]byte, 1)
	_, err := conn.Read(headerSizeBuf)
	if err != nil {
		return 0
	}
	// if headerSizeBuf[0] != 0 {
	// 	fmt.Println("\n Receive message from : ", conn.RemoteAddr())
	// 	fmt.Println("taille du header recu : ", headerSizeBuf[0])
	// }
	return int(headerSizeBuf[0])
}
