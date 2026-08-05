package keyencodedecode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// Chiffrement du tunnel une fois la clé de session établie.
//
// Le nonce est PRÉFIXÉ au chiffré, puis l'ensemble est encodé en base64. C'est
// exactement ce que fait le serveur : le format doit correspondre au caractère
// près, sinon l'authentification GCM échoue sans autre explication.

func EncryptAESGCMString(key []byte, plaintext string) (string, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plaintext), nil)), nil
}

func DecryptAESGCMString(key []byte, ciphertext []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return "", err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	if len(raw) < aead.NonceSize() {
		return "", errors.New("message trop court pour contenir un nonce")
	}
	nonce, body := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("clé AES de taille incorrecte, 32 octets attendus pour AES-256")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
