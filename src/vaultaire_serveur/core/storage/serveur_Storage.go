package storage

// Le suivi des connexions en ligne se fait maintenant via le registre
// vaultaire/ducky-network/sessionmgr (Manager.ListAuthenticated()), qui est
// protégé par mutex et indexé par SessionID. L'ancienne slice Serveur_Online
// était mutée sans synchronisation depuis plusieurs goroutines (une par
// connexion), ce qui pouvait corrompre les index pendant les suppressions
// concurrentes.
