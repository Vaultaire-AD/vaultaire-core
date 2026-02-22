package sshreq

import "sync"

var (
	requests = map[string]chan string{}
	mu       sync.Mutex
)
