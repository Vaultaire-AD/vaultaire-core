package userauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// computePasswordHash DOIT reproduire exactement la fonction utilisée à l'inscription
// (même ordre password/salt, même algo, même encodage) — remplace le corps si besoin
// pour qu'il matche bit à bit ce que tu as déjà en base.
func computePasswordHash(password, saltHex string) ([]byte, error) {
	saltRaw, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("salt hex invalide: %w", err)
	}
	h := sha256.New()
	h.Write(saltRaw)          // salt EN PREMIER (comme create_User)
	h.Write([]byte(password)) // puis password
	return h.Sum(nil), nil
}

func buildAuthMessage(username, serverNonce, sessionID string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s", username, serverNonce, sessionID))
}

// GenerateChallengeProof s'exécute côté client, là où le mot de passe existe
// brièvement en clair. Ni le mot de passe ni le hash ne quittent cette fonction :
// seul le proof (HMAC) hexadécimal retourné est envoyé au serveur.
func GenerateChallengeProof(username, password, salt, serverNonce, sessionID string) (string, error) {
	if username == "" || password == "" || salt == "" || serverNonce == "" || sessionID == "" {
		return "", errors.New("paramètre manquant")
	}

	passwordHash, err := computePasswordHash(password, salt)
	if err != nil {
		return "", err
	}
	defer func() {
		for i := range passwordHash {
			passwordHash[i] = 0
		} // wipe best-effort, la stack/heap Go n'est pas garantie nettoyée sinon
	}()

	authMessage := buildAuthMessage(username, serverNonce, sessionID)

	mac := hmac.New(sha256.New, passwordHash)
	mac.Write(authMessage)
	proof := mac.Sum(nil)

	return hex.EncodeToString(proof), nil
}
