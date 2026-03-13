package security

import (
	"crypto/sha256"
	"encoding/hex"
)

// ComparePasswords compares a provided password with a stored hash using a salt.
// It decodes the salt and hash from their hexadecimal representations, combines the salt with the password,
// hashes the salted password using SHA-256, and then compares the resulting hash with the stored hash.
func ComparePasswords(password, saltHex, hashHex string) bool {
	// Decode the salt from hex
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}

	// Combine the salt and the provided password
	saltedPassword := append(salt, []byte(password)...)

	// Hash the salted password
	hash := sha256.Sum256(saltedPassword)

	// Encode the hash to hex
	newHashHex := hex.EncodeToString(hash[:])

	// Compare the new hash with the provided hash
	return newHashHex == hashHex
}
