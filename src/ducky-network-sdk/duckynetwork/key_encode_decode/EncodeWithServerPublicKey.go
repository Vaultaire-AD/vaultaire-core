package keyencodedecode

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// EncryptMessageWithPublic chiffre pour le serveur, avant l'établissement de la
// clé de session.
func EncryptMessageWithPublic(publicKeyPEM, message string) ([]byte, error) {
	pub, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	if max := MaxOAEPPayload(pub.Size()); len(message) > max {
		// Refus explicite plutôt qu'une erreur opaque de la bibliothèque : sur
		// une trame trop longue, le message « message too long for RSA key »
		// n'indique ni la taille reçue ni la limite.
		return nil, fmt.Errorf("charge de %d octets, maximum %d pour cette clé", len(message), max)
	}
	return rsa.EncryptOAEP(oaepHash(), rand.Reader, pub, []byte(message), oaepLabel)
}
