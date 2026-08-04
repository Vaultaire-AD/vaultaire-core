package sshclient

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
	dbusers "vaultaire/core/database/db_users"
)

const challengeTTL = 30 * time.Second

type pendingChallenge struct {
	Nonce     string
	ExpiresAt time.Time
}

var challengeStore = struct {
	sync.Mutex
	m map[string]pendingChallenge
}{m: make(map[string]pendingChallenge)}

func buildAuthMessage(username, serverNonce, sessionID string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s", username, serverNonce, sessionID))
}

// IssueChallenge est appelé quand le client demande le salt/nonce pour se co.
// Il génère un nonce à usage unique, lié à sessionID, avec une durée de vie courte.
func IssueChallenge(sessionID string) (nonce string, err error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce = hex.EncodeToString(raw)

	challengeStore.Lock()
	challengeStore.m[sessionID] = pendingChallenge{
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(challengeTTL),
	}
	challengeStore.Unlock()

	return nonce, nil
}

// VerifyChallengeProof vérifie la preuve envoyée par le client, sans jamais
// avoir eu accès au mot de passe ni l'avoir reçu sur le réseau.
func VerifyChallengeProof(db *sql.DB, username, fullUsername, sessionID, clientProofHex string) (bool, error) {
	challengeStore.Lock()
	pc, ok := challengeStore.m[sessionID]
	if ok {
		delete(challengeStore.m, sessionID) // usage unique : consommé qu'il réussisse ou non
	}
	challengeStore.Unlock()

	if !ok {
		return false, errors.New("challenge inconnu ou déjà utilisé")
	}
	if time.Now().After(pc.ExpiresAt) {
		return false, errors.New("challenge expiré")
	}
	userID, err := dbusers.Get_User_ID_By_Username(db, username)
	if err != nil {
		return false, err
	}
	storedHash, err := dbusers.Get_User_PasswordHash_By_UserID(db, userID)
	if err != nil {
		return false, err
	}
	storedHashBytes, err := hex.DecodeString(storedHash)
	if err != nil {
		return false, errors.New("format de hash invalide en base")
	}
	authMessage := buildAuthMessage(fullUsername, pc.Nonce, sessionID)
	mac := hmac.New(sha256.New, storedHashBytes)
	mac.Write(authMessage)
	expectedProof := mac.Sum(nil)

	clientProof, err := hex.DecodeString(clientProofHex)
	if err != nil {
		return false, errors.New("format de preuve invalide")
	}

	// hmac.Equal = comparaison en temps constant, jamais bytes.Equal ou ==
	return hmac.Equal(expectedProof, clientProof), nil
}
