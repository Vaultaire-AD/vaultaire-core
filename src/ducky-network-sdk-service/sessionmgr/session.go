package sessionmgr

import (
	"duckynetworkclient/V1/duckynetwork/storage"
	"net"
	"sync"
	"time"
)

type SessionStatus int

const (
	SessionPending SessionStatus = iota
	SessionAuthenticated
	SessionFailed
)

type Session struct {
	// SessionID est la clé primaire, source de vérité de cette session
	// (voir NewSessionID). Le username, lui, n'est pas unique : un même
	// utilisateur (y compris "vaultaire") peut avoir plusieurs sessions
	// ouvertes en même temps.
	SessionID    string
	Username     string
	Conn         net.Conn
	DuckySession *storage.DuckySession
	Status       SessionStatus
	CreatedAt    time.Time
	LastSeen     time.Time
}
type Manager struct {
	// sessions est indexé par SessionID, jamais par username.
	sessions map[string]*Session
	mu       sync.RWMutex
	timeout  time.Duration
}
