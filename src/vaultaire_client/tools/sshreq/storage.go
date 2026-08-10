package sshreq

import (
	"sync"
	"vaultaire_client/pamstate"
)

var (
	// requests stocke les channels de réponse en attente, clés par nom d'utilisateur.
	requests = make(map[string]chan pamstate.AuthResult)
	// mu protège l'accès concurrent au dictionnaire requests.
	mu sync.RWMutex
)
