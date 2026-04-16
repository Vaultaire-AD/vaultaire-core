package balancer

import (
	"sync"

	duckynetwork "vaultaire_duckynetwork"
)

// Balancer maintient une liste de Cores et choisit la cible (stratégie: round-robin ou par charge).
type Balancer struct {
	mu    sync.RWMutex
	cores []duckynetwork.CoreInfo
	next  int
}

// New crée un balancer avec la liste initiale de Cores.
func New(cores []duckynetwork.CoreInfo) *Balancer {
	return &Balancer{cores: cores}
}

// UpdateCores remplace la liste des Cores (service discovery).
func (b *Balancer) UpdateCores(cores []duckynetwork.CoreInfo) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cores = cores
	if b.next >= len(b.cores) {
		b.next = 0
	}
}

// Select retourne le prochain Core à utiliser (round-robin). Retourne ("", "", false) si aucun Core.
func (b *Balancer) Select() (hostname, ip string, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cores) == 0 {
		return "", "", false
	}
	c := b.cores[b.next]
	b.next = (b.next + 1) % len(b.cores)
	return c.Hostname, c.IP, true
}

// Cores retourne une copie de la liste des Cores (pour métriques ou affichage).
func (b *Balancer) Cores() []duckynetwork.CoreInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]duckynetwork.CoreInfo, len(b.cores))
	copy(out, b.cores)
	return out
}
