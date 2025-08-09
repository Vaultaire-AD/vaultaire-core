package serveurcommunication

import (
	"net"
	"sync"
)

var activeConnections = make(map[string]net.Conn)
var mu sync.Mutex // Pour éviter les conditions de course

func storeConnection(username string, conn net.Conn) {
	mu.Lock()
	activeConnections[username] = conn
	mu.Unlock()
}

func GetConnection(username string) (net.Conn, bool) {
	mu.Lock()
	conn, exists := activeConnections[username]
	mu.Unlock()
	return conn, exists
}

func RemoveConnection(username string) {
	mu.Lock()
	delete(activeConnections, username)
	mu.Unlock()
}
