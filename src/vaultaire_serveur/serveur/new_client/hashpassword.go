package newclient

import (
	"DUCKY/serveur/logs"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

func hashPassword(password string) (string, string, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		logs.Write_Log("ERROR", "error generating salt: "+err.Error())
		return "", "", err
	}

	// Combine salt and password
	saltedPassword := append(salt, []byte(password)...)

	// Hash the salted password
	hash := sha256.Sum256(saltedPassword)

	// Encode the salt and hash to hex
	saltHex := hex.EncodeToString(salt)
	hashHex := hex.EncodeToString(hash[:])

	return saltHex, hashHex, nil
}
