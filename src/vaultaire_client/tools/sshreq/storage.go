package sshreq

import (
	"sync"
	"vaultaire_client/storage"
)

var (
	// On change chan string en chan storage.AuthResult
	requests = map[string]chan storage.AuthResult{}
	mu       sync.Mutex
)
