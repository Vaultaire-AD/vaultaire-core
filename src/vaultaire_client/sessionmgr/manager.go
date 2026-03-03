package sessionmgr

import (
	"fmt"
	"net"
	"time"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
)

func NewManager(timeout time.Duration) *Manager {
	m := &Manager{
		sessions: make(map[string]*Session),
		timeout:  timeout,
	}
	go m.cleanupLoop()
	return m
}

func (m *Manager) AddOrUpdate(username string, conn net.Conn, status SessionStatus, duckysession *storage.DuckySession) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[username] = &Session{
		Username:     username,
		DuckySession: duckysession, // Initialisé plus tard
		Conn:         conn,
		Status:       status,
		LastSeen:     time.Now(),
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
			// On ne check QUE le timeout d'inactivité
			// Si aucune donnée n'a transité depuis m.timeout
			if now.Sub(s.LastSeen) > m.timeout {
				logs.Write_log("WARNING", fmt.Sprintf("Session timeout pour l'utilisateur %s. Fermeture du tunnel.", user))
				if s.Conn != nil {
					_ = s.Conn.Close()
				}
				delete(m.sessions, user)
			}
		}
		m.mu.Unlock()
	}
}

// On supprime la fonction isConnClosed qui cassait les lectures en cours
func isConnClosed(conn net.Conn) bool {
	one := []byte{}
	_ = conn.SetReadDeadline(time.Now())
	_, err := conn.Read(one)
	return err != nil
}

// GetDuckySession permet de récupérer l'objet DuckySession associé à un utilisateur.
func (m *Manager) GetDuckySession(username string) (*storage.DuckySession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[username]
	if !ok || s.DuckySession == nil {
		return nil, false
	}

	return s.DuckySession, true
}
