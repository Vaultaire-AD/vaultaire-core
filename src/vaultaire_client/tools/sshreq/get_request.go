package sshreq

import "vaultaire_client/storage"

// Pop extrait et supprime le channel de réponse associé à un utilisateur.
// Retourne le channel et true si trouvé, sinon nil et false.
//
// Exemple d'utilisation dans le worker réseau :
//
//	if ch, ok := sshreq.Pop(user); ok {
//	    ch <- result
//	}
func Pop(user string) (chan storage.AuthResult, bool) {
	mu.Lock()
	defer mu.Unlock()
	ch, ok := requests[user]
	if ok {
		delete(requests, user)
	}
	return ch, ok
}
