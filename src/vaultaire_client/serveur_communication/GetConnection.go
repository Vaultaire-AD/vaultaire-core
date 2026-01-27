package serveurcommunication

import (
	"sync"
	"vaultaire_client/storage"
)

var activeConnections = make(map[string]storage.DuckySession)
var mu sync.Mutex // Pour éviter les conditions de course

func storeConnection(username string, duckysession storage.DuckySession) {
	mu.Lock()
	activeConnections[username] = duckysession
	mu.Unlock()
}

func GetConnection(username string) (storage.DuckySession, bool) {
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
