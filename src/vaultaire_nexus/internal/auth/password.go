package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Empreintes de mot de passe : PBKDF2-SHA256, bibliothèque standard.
//
// Format : pbkdf2-sha256$<itérations>$<sel b64>$<empreinte b64>
//
// Argon2id serait préférable ; il vit dans golang.org/x/crypto, que ce service
// n'embarque pas. 600 000 itérations suivent la recommandation OWASP 2023 pour
// PBKDF2-SHA256. L'empreinte ne protège ici que le compte local et les jetons :
// les mots de passe Vaultaire ne sont jamais stockés par Nexus.
const pbkdf2Iter = 600_000

// HashPassword rend l'empreinte d'un secret.
func HashPassword(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, secret, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword compare en temps constant.
func VerifyPassword(encoded, secret string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false, errors.New("empreinte de mot de passe illisible")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false, errors.New("empreinte : itérations invalides")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, err
	}
	got, err := pbkdf2.Key(sha256.New, secret, salt, iter, len(want))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// RandomSecret rend n octets aléatoires en base64 URL.
func RandomSecret(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
