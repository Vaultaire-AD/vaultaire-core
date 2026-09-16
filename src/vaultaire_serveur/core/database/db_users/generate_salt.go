package dbusers

import (
	"crypto/rand"
)

// Fonction pour générer un salt aléatoire
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}
