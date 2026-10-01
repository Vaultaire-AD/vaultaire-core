package tramesmanager

// Cadrage d'une trame Ducky sur le socket (TO-DO 101).
//
//	[1 octet : longueur du champ taille][2 octets : taille du corps, big-endian][corps]
//
// JUMEAU de vaultaire_serveur/ducky-network/trames_manager/cadrage.go : mêmes
// constantes, mêmes règles. Le SDK est partagé par l'agent Linux, le proxy,
// Nexus et le client Windows ; l'audit du 25/09 avait trouvé un garde-fou posé
// côté core et oublié ici. Toute règle changée d'un côté se change de l'autre.
//
// # Le premier octet n'a qu'UNE valeur légale
//
// Il annonce la longueur du champ taille, qui fait toujours deux octets. Toute
// autre valeur est une erreur de protocole : la connexion est fermée, car il
// n'existe aucun moyen de retrouver le début de la trame suivante. 0 en fait
// partie — la boucle de réception le sautait comme un « rien à lire », alors
// qu'aucun émetteur ne l'envoie.
//
// # io.ReadFull, jamais conn.Read
//
// conn.Read sur un tampon de N octets n'en promet qu'AU MOINS UN. Sur une
// liaison lente, la taille arrivait sur un octet, le corps tronqué, et la fin
// passait pour l'en-tête suivant. Ce fichier est le seul endroit du SDK qui
// lit une trame sur le socket ; ceux qui ont besoin d'une lecture synchrone
// passent par LireCorps.

import (
	"fmt"
	"io"
	"math"
)

// TailleChampTaille est la longueur, en octets, du champ taille. C'est la
// seule valeur que le premier octet d'une trame peut prendre.
const TailleChampTaille = 2

// TailleMaxCorps est la plus grande taille de corps que deux octets peuvent
// annoncer.
const TailleMaxCorps = math.MaxUint16

// ErreurCadrage signale un flux qui ne respecte pas le cadrage : la connexion
// doit être fermée.
type ErreurCadrage struct {
	Motif string
}

func (e *ErreurCadrage) Error() string {
	return "cadrage Ducky invalide : " + e.Motif
}

// LireCorps lit exactement taille octets — le corps d'une trame dont la taille
// vient d'être lue par Read_Message_Size.
func LireCorps(conn io.Reader, taille int) ([]byte, error) {
	if taille <= 0 || taille > TailleMaxCorps {
		return nil, &ErreurCadrage{Motif: fmt.Sprintf("taille de corps %d hors de [1, %d]", taille, TailleMaxCorps)}
	}
	corps := make([]byte, taille)
	if _, err := io.ReadFull(conn, corps); err != nil {
		return nil, err
	}
	return corps, nil
}
