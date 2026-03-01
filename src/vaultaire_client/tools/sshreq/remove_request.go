package sshreq

// Remove supprime simplement (utile en cas de timeout)
func Remove(user string) {
	mu.Lock()
	delete(requests, user)
	mu.Unlock()
}
