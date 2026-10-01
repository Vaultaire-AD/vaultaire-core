package tramesmanager

// Cadrage d'une trame Ducky sur le socket (TO-DO 101).
//
//	[1 octet : longueur du champ taille][2 octets : taille du corps, big-endian][corps]
//
// # Le premier octet n'a qu'UNE valeur légale
//
// Il annonce la longueur du champ « taille », et ce champ fait toujours deux
// octets : tout émetteur — core, SDK, enrôlement — l'écrit avec
// CompileHeaderSize sur un tampon de deux. Il était pourtant lu comme une
// longueur libre : `\x01\xff` faisait allouer un tampon d'UN octet, puis
// binary.BigEndian.Uint16 paniquait dessus. Sans authentification, en deux
// octets, et chaque panique écrivait une pile complète en CRITICAL dans le
// journal commun.
//
// Toute autre valeur que 2 est donc une erreur de protocole, refusée AVANT
// toute allocation, et la connexion est fermée : il n'existe aucun moyen de
// se resynchroniser sur un flux dont on ne sait plus où commence la trame
// suivante.
//
// # io.ReadFull, jamais conn.Read
//
// TCP a le droit de rendre moins d'octets que demandé. conn.Read sur un tampon
// de N octets n'en promet qu'AU MOINS UN. Une liaison lente rendait donc une
// taille sur un seul octet, ou un corps tronqué dont la fin passait pour
// l'en-tête suivant — sans attaquant, en échec d'authentification
// intermittent. Ce fichier est le seul endroit qui lit le socket Ducky : il ne
// doit jamais y avoir de conn.Read ailleurs dans ce paquet.
//
// # Le jumeau du SDK
//
// Le même cadrage est lu et écrit par ducky-network-sdk-service
// (trames_manager/cadrage.go), partagé par l'agent, le proxy, Nexus et le
// client Windows. Les deux fichiers portent les mêmes constantes et les mêmes
// règles : la première version de ce garde-fou n'avait été posée que d'un côté.

import (
	"fmt"
	"io"
	"math"
)

// TailleChampTaille est la longueur, en octets, du champ qui porte la taille
// du corps. C'est la seule valeur que le premier octet d'une trame peut
// prendre.
const TailleChampTaille = 2

// TailleMaxCorps est la plus grande taille de corps que deux octets peuvent
// annoncer. Au-delà, il n'existe aucune façon correcte d'émettre la trame.
const TailleMaxCorps = math.MaxUint16

// ErreurCadrage signale un flux qui ne respecte pas le cadrage : la connexion
// doit être fermée, aucune resynchronisation n'est possible.
type ErreurCadrage struct {
	Motif string
}

func (e *ErreurCadrage) Error() string {
	return "cadrage Ducky invalide : " + e.Motif
}

// lireTailleCorps lit le champ taille, dont la longueur vient d'être validée.
func lireTailleCorps(conn io.Reader) (int, error) {
	var champ [TailleChampTaille]byte
	if _, err := io.ReadFull(conn, champ[:]); err != nil {
		return 0, err
	}
	taille := int(champ[0])<<8 | int(champ[1])
	if taille == 0 {
		// Aucun émetteur n'envoie de corps vide : « askkey » et toute trame
		// chiffrée font au moins quelques octets. Un zéro ne peut venir que
		// d'un flux désynchronisé ou forgé.
		return 0, &ErreurCadrage{Motif: "corps annoncé vide"}
	}
	return taille, nil
}

// lireCorps lit exactement taille octets.
func lireCorps(conn io.Reader, taille int) ([]byte, error) {
	if taille <= 0 || taille > TailleMaxCorps {
		return nil, &ErreurCadrage{Motif: fmt.Sprintf("taille de corps %d hors de [1, %d]", taille, TailleMaxCorps)}
	}
	corps := make([]byte, taille)
	if _, err := io.ReadFull(conn, corps); err != nil {
		return nil, err
	}
	return corps, nil
}
