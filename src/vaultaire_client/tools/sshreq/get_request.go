package sshreq

func Pop(user string) (chan string, bool) {
	mu.Lock()
	ch, ok := requests[user]
	if ok {
		delete(requests, user)
	}
	mu.Unlock()
	return ch, ok
}
