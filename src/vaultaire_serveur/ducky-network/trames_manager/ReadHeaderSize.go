package tramesmanager

import (
	"fmt"
	"io"
	"net"
	"vaultaire/core/logs"
)

// Read_Header_Size lit le premier octet d'une trame et rend la longueur du
// champ taille — c'est-à-dire TailleChampTaille, ou 0 pour « fermer ».
//
// 0 couvre deux cas que l'appelant traite pareil : le pair est parti (EOF,
// délai écoulé), ou le premier octet n'est pas celui du protocole. Le second
// est journalisé en UNE ligne, sans pile : c'était la pile de la panique qui
// faisait de deux octets anonymes plusieurs kilo-octets de journal (TO-DO 101).
// Voir cadrage.go.
func Read_Header_Size(conn net.Conn) int {
	if conn == nil {
		return 0
	}
	var premier [1]byte
	if _, err := io.ReadFull(conn, premier[:]); err != nil {
		return 0
	}
	if int(premier[0]) != TailleChampTaille {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"ducky: trame refusée de %s : champ taille annoncé sur %d octet(s), %d attendus — connexion fermée",
			adresseDistante(conn), premier[0], TailleChampTaille))
		return 0
	}
	return TailleChampTaille
}

// adresseDistante tolère une connexion sans adresse (tests, net.Pipe).
func adresseDistante(conn net.Conn) string {
	if a := conn.RemoteAddr(); a != nil {
		return a.String()
	}
	return "?"
}
