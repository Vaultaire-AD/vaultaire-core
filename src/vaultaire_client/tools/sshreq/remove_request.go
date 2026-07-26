package sshreq

// Remove supprime l'enregistrement d'un utilisateur sans récupérer son channel.
// Utile principalement pour nettoyer les requêtes après un timeout.
func Remove(user string) {
	mu.Lock()
	defer mu.Unlock()
	delete(requests, user)
}
