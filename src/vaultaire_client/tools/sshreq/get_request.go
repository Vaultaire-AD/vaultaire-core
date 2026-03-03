package sshreq

import "vaultaire_client/storage"

// Pop récupère et supprime le channel de la liste
func Pop(user string) (chan storage.AuthResult, bool) {
	mu.Lock()
	ch, ok := requests[user]
	if ok {
		delete(requests, user)
	}
	mu.Unlock()
	return ch, ok
}
