package keydecodeencode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// EncryptAESGCMString chiffre un texte en string et renvoie un base64 string
func EncryptAESGCMString(key []byte, plaintext string) (string, error) {
	if len(key) != 32 {
		return "", errors.New("clé AES doit faire 32 octets pour AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	// encode en base64 pour transmettre sous forme de string
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAESGCMString déchiffre un string base64 chiffré avec EncryptAESGCMString
func DecryptAESGCMString(key []byte, ciphertextB64 []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("clé AES doit faire 32 octets pour AES-256")
	}

	// 🔥 ÉTAPE MANQUANTE
	ciphertext, err := base64.StdEncoding.DecodeString(string(ciphertextB64))
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext trop court")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
