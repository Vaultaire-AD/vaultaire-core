package client

import (
	"vaultaire/core/logs"
)

// addOnlineServerToTable trace l'entrée en ligne d'un serveur pair (username
// "vaultaire"). L'état lui-même est déjà porté par sessionmgr.Sessions
// (SetIdentity + SetStatus appelés par l'appelant juste avant) : le
// heartbeat dans duckyGoroutine.go parcourt maintenant TOUTES les sessions
// authentifiées (sessionmgr.Sessions.ListAuthenticated()), pas seulement
// celles en "vaultaire". Cette fonction ne fait donc plus que logguer, mais
// elle garde son nom pour que l'étape reste visible et grep-able dans le
// flux de CheckAuth.
func addOnlineServerToTable(sessionID, username, clientSoftwareID string) {
	logs.Write_LogCodeMeta("INFO", logs.CodeNone,
		"New peer server online: "+clientSoftwareID, logs.WithMeta(sessionID, username))
}
