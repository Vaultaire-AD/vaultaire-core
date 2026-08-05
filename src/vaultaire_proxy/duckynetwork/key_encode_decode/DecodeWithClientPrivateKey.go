package keyencodedecode

import (
	"crypto/rand"
	"crypto/rsa"
)

// DecryptMessageWithPrivate déchiffre ce que le serveur nous a chiffré.
//
// Un échec ici ne signifie pas seulement « message illisible » : la réponse du
// core est chiffrée avec la clé publique de l'identifiant annoncé. Ne pas savoir
// la lire signifie que le core ne nous reconnaît plus sous cet identifiant.
func DecryptMessageWithPrivate(privateKeyPEM string, ciphertext []byte) (string, error) {
	priv, err := ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	plain, err := rsa.DecryptOAEP(oaepHash(), rand.Reader, priv, ciphertext, oaepLabel)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
