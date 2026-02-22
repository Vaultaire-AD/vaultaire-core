package sshreq

func Count() int {
	mu.Lock()
	n := len(requests)
	mu.Unlock()
	return n
}
