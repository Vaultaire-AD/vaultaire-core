package sshreq

import (
	"sync"
	"vaultaire_client/storage"
)

var (
	// requests stocke les channels de réponse en attente, clés par nom d'utilisateur.
	requests = make(map[string]chan storage.AuthResult)
	// mu protège l'accès concurrent au dictionnaire requests.
	mu sync.RWMutex
)
