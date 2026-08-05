// Package tramesmanager lit le flux, déchiffre et aiguille.
package tramesmanager

import (
	"io"
	"net"
)

// Read_Header_Size lit l'octet qui annonce la taille du champ de taille.
//
// Le protocole est en trois temps : un octet qui dit combien d'octets portent la
// taille, puis ces octets, puis la charge. Une lecture partielle ici
// désynchroniserait tout le reste du flux, d'où io.ReadFull.
func Read_Header_Size(conn net.Conn) (int, error) {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	return int(buf[0]), nil
}
