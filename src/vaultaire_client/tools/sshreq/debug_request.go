package sshreq

// Count donne le nombre de requêtes en cours
func Count() int {
	mu.Lock()
	defer mu.Unlock()
	return len(requests)
}
