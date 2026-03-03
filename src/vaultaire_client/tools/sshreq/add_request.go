package sshreq

import "vaultaire_client/storage"

// Register enregistre le channel pour un utilisateur
func Register(user string, ch chan storage.AuthResult) {
	mu.Lock()
	requests[user] = ch
	mu.Unlock()
}
