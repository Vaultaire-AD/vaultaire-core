package tramesmanager

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Read_Message_Size lit la taille de la charge utile.
func Read_Message_Size(conn net.Conn, headerSize int) (int, error) {
	if headerSize != 2 {
		// Le protocole n'a jamais émis autre chose que deux octets. Accepter une
		// autre taille reviendrait à deviner l'ordre des octets d'un format qui
		// n'existe pas.
		return 0, fmt.Errorf("en-tête de taille inattendu : %d octet(s), 2 attendus", headerSize)
	}
	buf := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(buf)), nil
}
