package sshreq

// Count retourne le nombre actuel de requêtes en attente de réponse.
func Count() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(requests)
}
