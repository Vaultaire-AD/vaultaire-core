package ldapsessionmanager

import (
	"fmt"
	"net"
	"sync"
	"vaultaire/core/logs"
)

type LDAPSession struct {
	Conn        net.Conn
	Username    string
	IsBound     bool
	IsAnonymous bool
	UserDN      string // DN complet s'il est connu
}

var (
	sessionStore   = make(map[net.Conn]*LDAPSession)
	sessionStoreMu sync.RWMutex
)

func SetAnonymousBindInfo(conn net.Conn) {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()

	if sess, ok := sessionStore[conn]; ok {
		sess.IsBound = true
		sess.IsAnonymous = true
		// Nom VIDE, et surtout pas « anonymous ».
		//
		// Les contrôles en aval interrogent le RBAC avec cette chaîne. Un compte
		// réellement nommé « anonymous » verrait donc ses permissions accordées aux
		// sessions non authentifiées.
		//
		// Aujourd'hui le dispatcheur interdit à un anonyme toute recherche autre
		// que RootDSE avant d'y arriver : la protection tient à un contrôle
		// distant, pas à la valeur. Une chaîne vide ne peut désigner aucun compte,
		// donc ne peut pas entrer en collision — la protection devient locale.
		sess.Username = ""
	}
}

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

// ResetBindInfo ramène la session à l'état non authentifié, SANS la supprimer.
//
// # Pourquoi ce n'est pas DeleteLDAPSession
//
// Supprimer l'entrée alors que la connexion vit encore laissait les
// gestionnaires suivants lire une session absente. Le chemin de recherche
// RootDSE ne vérifiait pas ce cas et déréférençait un pointeur nil : le serveur
// entier s'arrêtait, sur trois paquets envoyés par un inconnu.
//
// Une session existe tant que la connexion existe. Ce qui change à un refus,
// c'est l'IDENTITÉ portée par la session, pas son existence.
//
// C'est aussi ce qu'impose la RFC 4511 §4.2.1 : un bind en échec laisse la
// connexion dans l'état anonyme. Avant, un client authentifié comme alice qui
// ratait un bind sur bob restait alice.
func ResetBindInfo(conn net.Conn) {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()

	if sess, ok := sessionStore[conn]; ok {
		sess.IsBound = false
		sess.IsAnonymous = false
		sess.Username = ""
		sess.UserDN = ""
		return
	}
	// La session a disparu — connexion en cours de fermeture. On la recrée pour
	// que les gestionnaires suivants trouvent toujours une valeur non nulle.
	sessionStore[conn] = &LDAPSession{Conn: conn}
}

// ClearSession supprime la session. À n'appeler QUE lorsque la connexion se
// ferme — voir ResetBindInfo pour un refus en cours de connexion.
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
