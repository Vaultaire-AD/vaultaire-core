package sessionmgr

import (
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
	Username string
	Conn     net.Conn
	Status   SessionStatus
	LastSeen time.Time
}
type Manager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	timeout  time.Duration
}
