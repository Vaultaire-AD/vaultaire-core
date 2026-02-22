package sshreq

func Register(user string, ch chan string) {
	mu.Lock()
	requests[user] = ch
	mu.Unlock()
}
