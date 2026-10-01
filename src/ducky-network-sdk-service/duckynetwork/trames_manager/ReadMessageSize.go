package tramesmanager

import (
	"fmt"
	"io"
	"net"
)

// Read_Message_Size lit la taille du corps, sur exactement deux octets.
//
// headerSize est vérifié, jamais employé pour dimensionner un tampon. Une
// erreur veut dire « fermer la connexion ». Voir cadrage.go.
func Read_Message_Size(conn net.Conn, headerSize int) (int, error) {
	if conn == nil {
		return 0, fmt.Errorf("connexion absente")
	}
	if headerSize != TailleChampTaille {
		return 0, &ErreurCadrage{Motif: fmt.Sprintf("champ taille de %d octet(s), %d attendus", headerSize, TailleChampTaille)}
	}
	var champ [TailleChampTaille]byte
	if _, err := io.ReadFull(conn, champ[:]); err != nil {
		return 0, err
	}
	taille := int(champ[0])<<8 | int(champ[1])
	if taille == 0 {
		return 0, &ErreurCadrage{Motif: "corps annoncé vide"}
	}
	return taille, nil
}
