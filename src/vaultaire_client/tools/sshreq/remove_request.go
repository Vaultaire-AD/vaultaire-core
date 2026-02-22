package sshreq

func Remove(user string) {
	mu.Lock()
	delete(requests, user)
	mu.Unlock()
}
