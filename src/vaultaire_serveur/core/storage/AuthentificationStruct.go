package storage

// Authentification est un défi en attente : le serveur a émis une 02_02, il
// attend la 02_03 qui lui renverra le jeton.
//
// # Le champ Password a été SUPPRIMÉ
//
// Il portait le mot de passe EN CLAIR, recopié depuis la trame reçue, et
// personne ne le lisait jamais — ni la vérification du défi, ni la fermeture de
// session. Le serveur gardait donc en mémoire, dans une carte de paquet, le mot
// de passe de chaque compte en cours d'authentification, sans usage.
//
// Combiné à l'absence de purge (voir authStore), cela faisait s'accumuler un
// mot de passe en clair par authentification abandonnée, pour toute la durée de
// vie du processus. Un vidage mémoire du core les livrait tous.
//
// Le mot de passe est vérifié à la trame 02_01 par dbusers.VerifierMotDePasse
// et n'a aucune raison de survivre à cet appel.
type Authentification struct {
	RandomAuth       []byte
	AuthID           string
	Username         string
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
