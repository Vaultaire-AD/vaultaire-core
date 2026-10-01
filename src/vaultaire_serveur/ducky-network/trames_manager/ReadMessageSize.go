package tramesmanager

import (
	"fmt"
	"net"
)

// Read_Message_Size lit la taille du corps, sur exactement deux octets.
//
// headerSize est ce qu'a rendu Read_Header_Size. Il n'est plus utilisé pour
// dimensionner un tampon — c'est ce qui permettait la panique du TO-DO 101 —,
// seulement vérifié : un appelant qui l'aurait obtenu autrement est refusé.
//
// Une erreur veut dire « fermer la connexion » : la position dans le flux est
// perdue.
func Read_Message_Size(conn net.Conn, headerSize int) (int, error) {
	if conn == nil {
		return 0, fmt.Errorf("connexion absente")
	}
	if headerSize != TailleChampTaille {
		return 0, &ErreurCadrage{Motif: fmt.Sprintf("champ taille de %d octet(s), %d attendus", headerSize, TailleChampTaille)}
	}
	return lireTailleCorps(conn)
}
