package duckynetwork

import (
	"fmt"
	"time"
	db "vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/sendmessage"
	"vaultaire/ducky-network/sessionmgr"
	tm "vaultaire/ducky-network/trames_manager"
)

//
// --- Connexions client ---
//

// handleConnection gère une nouvelle connexion client.
func handleConnection(duckysession *storage.DuckySession) {
	logs.Write_LogCodeMeta("INFO", logs.CodeNone,
		"New connection established: "+duckysession.Conn.RemoteAddr().String(),
		logs.WithMeta(duckysession.SessionID, ""))

	for processIncomingMessage(duckysession) {
		// rien à mettre ici : processIncomingMessage gère tout
	}
}

// processIncomingMessage lit et traite un message du client.
// Retourne false si rien n’a pu être lu (connexion probablement interrompue).
func processIncomingMessage(duckysession *storage.DuckySession) bool {
	headerSize := tm.Read_Header_Size(duckysession.Conn)
	if headerSize == 0 {
		return false
	}

	sessionmgr.Sessions.Touch(duckysession.SessionID)

	messageSize := tm.Read_Message_Size(duckysession.Conn, headerSize)
	tm.MessageReader(duckysession, messageSize)
	return true
}

// closeConnection retire la session du registre (ce qui ferme le socket) et
// log la fin de connexion avec son SessionID, pour rester traçable même
// quand plusieurs connexions se terminent en même temps.
func closeConnection(duckysession *storage.DuckySession) {
	if duckysession == nil || duckysession.Conn == nil {
		return
	}
	sessionmgr.Sessions.RemoveSession(duckysession.SessionID)
	logs.Write_LogCodeMeta("INFO", logs.CodeNone, "Connection closed", logs.WithMeta(duckysession.SessionID, ""))
}

//
// --- Vérification serveurs en ligne ---
//

// checkServeurOnline lance une vérification périodique des serveurs en ligne.
func checkServeurOnline() {
	ticker := time.NewTicker(time.Duration(storage.ServerCheckOnlineTimer) * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		verifyServersOnline()
	}
}

// verifyServersOnline parcourt TOUTES les sessions authentifiées (anciens
// Serveur_Online, qui ne couvrait que les pairs "vaultaire") et vérifie leur
// état. ListAuthenticated renvoie un instantané pris sous verrou : on peut
// le parcourir et supprimer des entrées du registre sans risque de
// corruption d'index concurrente.
func verifyServersOnline() {
	for _, sess := range sessionmgr.Sessions.ListAuthenticated() {
		pingServer(sess)
		CheckClientOnline(sess)

	}
}

func CheckClientOnline(sess *sessionmgr.Session) bool {

	logs.Write_Log("INFO", fmt.Sprintf(
		"Check session ID=%s User=%s LastSeen=%s",
		sess.SessionID,
		sess.Username,
		sess.LastSeen.Format(time.RFC3339),
	))

	if sessionmgr.Sessions.IsSessionExpired(sess) {

		logs.Write_Log("WARNING", fmt.Sprintf(
			"Session supprimée ID=%s User=%s (LastSeen trop ancien)",
			sess.SessionID,
			sess.Username,
		))

		removeOfflineServer(sess)
		return false
	} else {

		logs.Write_Log("INFO", fmt.Sprintf(
			"Session maintenue ID=%s User=%s",
			sess.SessionID,
			sess.Username,
		))
	}
	return true
}

// pingServer envoie un message heartbeat à une session et retourne true si OK.
func pingServer(sess *sessionmgr.Session) {
	content := "02_11\nserveur_central\n" + sess.SessionID + "\nclient_giveinformation"
	err := sendmessage.SendMessage(content, sess.ClientSoftwareID, sess.DuckySession)
	if err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone,
			"Error sending heartbeat to "+sess.ClientSoftwareID+": "+err.Error(),
			logs.WithMeta(sess.SessionID, sess.Username))
		return
	}
	return
}

// removeOfflineServer retire une session offline du registre (ce qui ferme
// le socket) et nettoie l'entrée de login associée en DB.
func removeOfflineServer(sess *sessionmgr.Session) {
	sessionmgr.Sessions.RemoveSession(sess.SessionID)

	err := db.DeleteDidLogin(db.GetDatabase(), sess.Username, sess.ClientSoftwareID)
	meta := logs.WithMeta(sess.SessionID, sess.Username)
	if err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone,
			"Error deleting session for "+sess.ClientSoftwareID+": "+err.Error(), meta)
	} else {
		logs.Write_LogCodeMeta("INFO", logs.CodeNone,
			"Server "+sess.ClientSoftwareID+" is offline and removed from online list", meta)
	}
}

//
// --- Nettoyage sessions ---
//

// clearSession supprime périodiquement les sessions expirées.
func clearSession() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cleanExpiredSessions()
	}
}

// cleanExpiredSessions nettoie une fois les sessions expirées dans la DB.
func cleanExpiredSessions() {
	err := db.CleanUpExpiredSessions(db.GetDatabase())
	if err != nil {
		logs.Write_Log("ERROR", "Error during cleanup of user sessions: "+err.Error())
	}
}
