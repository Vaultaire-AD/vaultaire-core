package client

import (
	"sync"
	"vaultaire/core/storage"
)

// authStore garde les challenges d'authentification en attente, indexés par
// AuthID et protégés par mutex.
//
// Ça remplace l'ancienne storage.StorageAuth : une slice globale mutée
// depuis n'importe quelle goroutine de connexion (une par client connecté)
// sans aucune synchronisation, via des patterns
// append(slice[:i], slice[i+1:]...). Deux logins concurrents pouvaient
// corrompre les index pendant une suppression, faire disparaître la
// mauvaise entrée, voire paniquer.
var authStore = struct {
	mu sync.Mutex
	m  map[string]storage.Authentification
}{m: make(map[string]storage.Authentification)}

// storeAuth enregistre un challenge en attente.
func storeAuth(auth storage.Authentification) {
	authStore.mu.Lock()
	defer authStore.mu.Unlock()
	authStore.m[auth.AuthID] = auth
}

// GetRandomAuthByAuthID récupère le challenge et le username associés à un
// AuthID, puis le retire du store (usage unique). Retourne (nil, "") si
// l'AuthID est inconnu (déjà consommé, expiré côté logique, ou jamais émis).
func GetRandomAuthByAuthID(authIDToFind string) ([]byte, string) {
	authStore.mu.Lock()
	defer authStore.mu.Unlock()

	auth, ok := authStore.m[authIDToFind]
	if !ok {
		return nil, ""
	}
	delete(authStore.m, authIDToFind)
	return auth.RandomAuth, auth.Username
}

// DeleteAuthByID retire un challenge en attente par AuthID, sans erreur si
// absent.
func DeleteAuthByID(authID string) {
	authStore.mu.Lock()
	defer authStore.mu.Unlock()
	delete(authStore.m, authID)
}
