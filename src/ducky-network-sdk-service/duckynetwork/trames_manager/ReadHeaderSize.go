package tramesmanager

import (
	"fmt"
	"io"
	"net"
)

// Read_Header_Size lit le premier octet d'une trame et rend la longueur du
// champ taille, toujours TailleChampTaille. Toute autre valeur est une
// ErreurCadrage : l'appelant doit fermer la connexion. Voir cadrage.go.
func Read_Header_Size(conn net.Conn) (int, error) {
	if conn == nil {
		return 0, fmt.Errorf("connexion absente")
	}
	var premier [1]byte
	if _, err := io.ReadFull(conn, premier[:]); err != nil {
		return 0, err // la vraie erreur : EOF, délai écoulé…
	}
	if int(premier[0]) != TailleChampTaille {
		return 0, &ErreurCadrage{Motif: fmt.Sprintf(
			"champ taille annoncé sur %d octet(s), %d attendus", premier[0], TailleChampTaille)}
	}
	return TailleChampTaille, nil
}
