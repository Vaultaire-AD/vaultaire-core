// Package sshreq gère le registre de réponses asynchrones pour les requêtes PAM/SSH.
// Il permet d'associer une requête réseau sortante à son attente locale (channel).
package sshreq

import (
	"vaultaire_client/storage"
)

// Register enregistre un channel de réponse pour un utilisateur donné.
// Si un channel existait déjà pour cet utilisateur, il sera remplacé.
//
// Exemple d'utilisation :
//
//	respChan := make(chan storage.AuthResult, 1)
//	sshreq.Register("alice@corp.local", respChan)
//	defer sshreq.Remove("alice@corp.local")
func Register(user string, ch chan storage.AuthResult) {
	mu.Lock()
	defer mu.Unlock()
	requests[user] = ch
}
