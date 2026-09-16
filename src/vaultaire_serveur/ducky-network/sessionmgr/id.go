package sessionmgr

import (
	"crypto/rand"
	"fmt"
)

// NewSessionID génère un identifiant unique (UUID v4) attribué à une
// connexion dès son acceptation par le listener, avant même le premier
// octet lu sur le socket. Une fois la poignée de main initiale terminée
// (première trame 01_01), Rekey aligne cet ID sur le SessionIntegritykey
// réellement utilisé dans chaque trame du protocole : après ça, le même
// identifiant sert à la fois de clé de log et de clé réseau, grep-able de
// façon interchangeable.
func NewSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Cas extrêmement improbable : valeur dégradée mais toujours
		// utilisable comme clé de map (juste pas garantie unique dans
		// l'absolu).
		return fmt.Sprintf("degraded-%x", b)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
