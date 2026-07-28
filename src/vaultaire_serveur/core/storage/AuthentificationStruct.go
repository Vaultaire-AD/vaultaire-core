package storage

type Authentification struct {
	RandomAuth       []byte
	AuthID           string
	Username         string
	Password         string
	ClientSoftwareID string
}

type Authentification_Challenge_server struct {
	AuthID    string
	Challenge string
}

// Le stockage des challenges en attente (StorageAuth) a été déplacé dans le
// package vaultaire/ducky-network/authentification/client (voir
// authStore.go) : c'est maintenant une map protégée par mutex plutôt qu'une
// slice globale mutée sans synchronisation depuis plusieurs goroutines.
