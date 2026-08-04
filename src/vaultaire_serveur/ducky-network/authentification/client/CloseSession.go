package client

import (
	"vaultaire/core/database"
	dbsessions "vaultaire/core/database/db_sessions"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/sessionmgr"
)

// closeSession gère la fermeture propre de la session client : nettoyage DB,
// cache d'auth en mémoire, clé de session, puis retrait du registre (qui
// ferme le socket). Chaque étape est logguée avec le même meta
// (SessionID + username), donc un grep sur le SessionID retrouve tout le
// déroulé d'UN logout précis, même si plusieurs sessions se ferment en même
// temps.
func closeSession(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) {
	sessionID := ""
	if duckysession != nil {
		sessionID = duckysession.SessionID
	}
	meta := logs.WithMeta(sessionID, trames_content.Username)

	// 1. Nettoyage de la base de données
	if err := dbsessions.DeleteDidLogin(database.DB, trames_content.Username, trames_content.ClientSoftwareID); err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone, "DB cleanup failed: "+err.Error(), meta)
	}

	// 2. Nettoyage de l'auth en mémoire (cache applicatif des challenges en
	// attente). Note : ClientSoftwareID n'est normalement pas un AuthID
	// valide ici (comportement préexistant, hors périmètre de ce nettoyage) ;
	// gardé tel quel pour ne pas changer le comportement.
	DeleteAuthByID(trames_content.ClientSoftwareID)

	if duckysession == nil {
		logs.Write_LogCodeMeta("INFO", logs.CodeNone, "Clean logout completed (no active DuckySession)", meta)
		return
	}

	// 3. Invalidation immédiate des droits et écrasement de la clé de session
	// en mémoire (anti-forensics) : on ne se contente pas de mettre à nil, on
	// remplit de zéros.
	duckysession.IsSafe = false
	if duckysession.SessionKey != nil {
		for i := range duckysession.SessionKey {
			duckysession.SessionKey[i] = 0
		}
		duckysession.SessionKey = nil
	}

	// 4. Retrait du registre de sessions : ferme le socket réseau et
	// dé-référence la session en un seul point. Le handleConnection qui
	// possède cette connexion sortira de sa boucle de lecture juste après (la
	// suppression est idempotente, pas de risque de double-log confus).
	logs.Write_LogCodeMeta("DEBUG", logs.CodeNone, "Closing TCP connection", meta)
	sessionmgr.Sessions.RemoveSession(sessionID)

	logs.Write_LogCodeMeta("INFO", logs.CodeNone, "Clean logout completed", meta)
}
