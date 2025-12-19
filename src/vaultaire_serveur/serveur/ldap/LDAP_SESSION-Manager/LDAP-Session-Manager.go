package ldapsessionmanager

import (
	"DUCKY/serveur/logs"
	"fmt"
	"net"
	"sync"
)

type LDAPSession struct {
	Conn     net.Conn
	Username string
	IsBound  bool
	UserDN   string // DN complet s'il est connu
}

var (
	sessionStore   = make(map[net.Conn]*LDAPSession)
	sessionStoreMu sync.RWMutex
)

// Créer une nouvelle session
func InitLDAPSession(conn net.Conn) {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()

	sessionStore[conn] = &LDAPSession{
		Conn:    conn,
		IsBound: false,
	}
	logs.Write_Log("INFO", fmt.Sprintf("Nouvelle session LDAP créée pour %s", conn.RemoteAddr()))
}

// Récupérer une session existante
func GetLDAPSession(conn net.Conn) (*LDAPSession, bool) {
	sessionStoreMu.RLock()
	defer sessionStoreMu.RUnlock()

	sess, ok := sessionStore[conn]
	return sess, ok
}

// Mettre à jour les infos du bind
func SetBindInfo(conn net.Conn, username string, userDN string) {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()

	if sess, ok := sessionStore[conn]; ok {
		sess.IsBound = true
		sess.Username = username
		sess.UserDN = userDN
	}
}

func ClearSession(c net.Conn) {
	DeleteLDAPSession(c)
}

// Supprimer la session (à la fermeture de connexion)
func DeleteLDAPSession(conn net.Conn) {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()

	delete(sessionStore, conn)
	logs.Write_Log("INFO", fmt.Sprintf("Session LDAP supprimée pour %s", conn.RemoteAddr()))
}

func ListActiveSessions() []LDAPSession {
	sessionStoreMu.RLock()
	defer sessionStoreMu.RUnlock()

	sessions := make([]LDAPSession, 0, len(sessionStore))
	for _, s := range sessionStore {
		sessions = append(sessions, *s)
	}
	return sessions
}
