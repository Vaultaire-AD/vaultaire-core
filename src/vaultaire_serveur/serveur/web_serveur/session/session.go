package session

// 📁 vaultaire/serveur/webserveur/session/session.go

import (
	"vaultaire/serveur/logs"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type Session struct {
	Username  string
	ExpiresAt time.Time
}

var (
	sessions = make(map[string]Session)
	mu       sync.RWMutex
	duration = 30 * time.Minute
)

// Génère un token aléatoire
func generateToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebSession, "session: token generation failed: "+err.Error())
	}
	return hex.EncodeToString(b)
}

// Crée une nouvelle session
func CreateSession(username string) string {
	token := generateToken()
	mu.Lock()
	defer mu.Unlock()
	sessions[token] = Session{
		Username:  username,
		ExpiresAt: time.Now().Add(duration),
	}
	return token
}

// Valide le token et retourne le username
func ValidateToken(token string) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()
	session, exists := sessions[token]
	if !exists || session.ExpiresAt.Before(time.Now()) {
		return "", false
	}
	return session.Username, true
}
