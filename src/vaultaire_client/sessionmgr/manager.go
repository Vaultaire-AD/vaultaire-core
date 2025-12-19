package sessionmgr

import (
	"net"
	"time"
)

func NewManager(timeout time.Duration) *Manager {
	m := &Manager{
		sessions: make(map[string]*Session),
		timeout:  timeout,
	}
	go m.cleanupLoop()
	return m
}

func (m *Manager) AddOrUpdate(username string, conn net.Conn, status SessionStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[username] = &Session{
		Username: username,
		Conn:     conn,
		Status:   status,
		LastSeen: time.Now(),
	}
}

func (m *Manager) GetStatus(username string) (SessionStatus, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[username]
	if !ok {
		return SessionFailed, false
	}
	return s.Status, true
}

func (m *Manager) Delete(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[username]; ok {
		_ = s.Conn.Close()
		delete(m.sessions, username)
	}
}

func (m *Manager) Touch(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[username]; ok {
		s.LastSeen = time.Now()
	}
}

func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		m.mu.Lock()
		for user, s := range m.sessions {
			// Conn fermée OU timeout
			if s.Conn == nil ||
				isConnClosed(s.Conn) ||
				now.Sub(s.LastSeen) > m.timeout {

				if s.Conn != nil {
					_ = s.Conn.Close()
				}
				delete(m.sessions, user)
			}
		}
		m.mu.Unlock()
	}
}

func isConnClosed(conn net.Conn) bool {
	one := []byte{}
	_ = conn.SetReadDeadline(time.Now())
	_, err := conn.Read(one)
	return err != nil
}
