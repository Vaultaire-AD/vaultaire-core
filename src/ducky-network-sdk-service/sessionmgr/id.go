package sessionmgr

import (
	"crypto/rand"
	"fmt"
)

// NewSessionID génère un identifiant unique (UUID v4) pour une nouvelle
// DuckySession. Cet ID est purement local au client : il n'a aucun rapport
// avec le SessionIntegritykey émis par le serveur pendant la poignée de
// main. Il existe uniquement pour que le client puisse désigner sans
// ambiguïté une connexion précise (logs, lookup, fermeture ciblée), y
// compris quand plusieurs sessions partagent le même username.
func NewSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Cas extrêmement improbable : on retombe sur une valeur dégradée
		// mais toujours utilisable comme clé de map (juste pas garantie
		// unique dans l'absolu).
		return fmt.Sprintf("degraded-%x", b)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
