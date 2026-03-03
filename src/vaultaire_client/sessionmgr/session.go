package sessionmgr

import (
	"net"
	"sync"
	"time"
	"vaultaire_client/storage"
)

type SessionStatus int

const (
	SessionPending SessionStatus = iota
	SessionAuthenticated
	SessionFailed
)

type Session struct {
	Username     string
	Conn         net.Conn
	DuckySession *storage.DuckySession
	Status       SessionStatus
	LastSeen     time.Time
}
type Manager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	timeout  time.Duration
}
