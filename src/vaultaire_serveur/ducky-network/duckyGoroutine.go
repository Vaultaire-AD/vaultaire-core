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
	// Le nettoyage est en defer, et il ne l'était pas.
	//
	// closeConnection existait déjà mais n'avait AUCUN appelant : à la sortie de
	// la boucle — lecture en échec, donc pair parti — le socket restait ouvert
	// côté serveur et l'entrée restait dans le registre. Le balayage périodique
	// ne rattrapait que les sessions authentifiées, donc une connexion qui
	// tombait avant d'avoir fini sa poignée de main n'était jamais nettoyée.
	//
	// En defer plutôt qu'après la boucle : une panique dans un handler doit
	// aussi fermer la connexion, pas la laisser derrière elle.
	defer closeConnection(duckysession)

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

// Délais d'inactivité du balayage.
//
// authIdleTimeout couvre plusieurs cycles de heartbeat : le ticker envoie un
// 02_11 toutes les ServerCheckOnlineTimer minutes (2 par défaut), et la réponse
// du client rafraîchit LastSeen. Cinq minutes laissent donc passer deux
// battements manqués avant de conclure que le pair est parti.
//
// handshakeIdleTimeout s'applique à TOUT LE RESTE — sessions en attente, en
// échec. Un client réel enchaîne accept(), 01_01 et 02_01 en une fraction de
// seconde ; soixante secondes sont déjà très généreuses pour une liaison lente
// ou un appareil peu puissant. Leur accorder les cinq minutes des sessions
// authentifiées reviendrait à offrir un socket ouvert, une goroutine et une
// entrée de registre à quiconque ouvre une connexion TCP sans rien envoyer.
const (
	authIdleTimeout      = 5 * time.Minute
	handshakeIdleTimeout = 60 * time.Second
)

// verifyServersOnline envoie les battements de cœur puis ferme les sessions
// inactives.
//
// DEUX TEMPS, et l'ordre compte. Le heartbeat d'abord : il ne concerne que les
// sessions authentifiées, et une réponse rafraîchit LastSeen, ce qui évite de
// couper au balayage suivant un pair qui vient de répondre. Le balayage
// ensuite, sur TOUTES les sessions.
//
// C'est ce second point qui change. L'ancienne version ne parcourait que
// ListAuthenticated() : les sessions restées en attente — celles qu'un
// attaquant obtient sans posséder le moindre identifiant — n'étaient jamais
// examinées, donc jamais fermées.
func verifyServersOnline() {
	for _, sess := range sessionmgr.Sessions.ListAuthenticated() {
		pingServer(sess)
	}

	for _, stale := range sessionmgr.Sessions.StaleSessions(authIdleTimeout, handshakeIdleTimeout) {
		dropStaleSession(stale)
	}

	if counts := sessionmgr.Sessions.CountByStatus(); len(counts) > 0 {
		logs.Write_Log("DEBUG", fmt.Sprintf(
			"sessions ducky : %d authentifiée(s), %d en attente, %d en échec",
			counts[sessionmgr.SessionAuthenticated],
			counts[sessionmgr.SessionPending],
			counts[sessionmgr.SessionFailed]))
	}
}

// dropStaleSession ferme une session inactive et nettoie ce qui va avec.
//
// Le nettoyage en base ne concerne QUE les sessions authentifiées.
// DeleteDidLogin prend un username et un ClientSoftwareID : sur une session en
// attente, les deux sont vides ou simplement annoncés — jamais prouvés. Les
// passer effacerait une ligne de connexion appartenant à quelqu'un d'autre, ou,
// avec des champs vides, ferait porter la suppression sur ce que la requête
// voudra bien faire correspondre. Une connexion qui n'a jamais abouti n'a rien
// écrit en base : il n'y a rien à y retirer.
func dropStaleSession(stale sessionmgr.StaleSession) {
	sessionmgr.Sessions.RemoveSession(stale.SessionID)

	meta := logs.WithMeta(stale.SessionID, stale.Username)

	if stale.Status != sessionmgr.SessionAuthenticated {
		// Journalisé en INFO et non en WARNING : sur un serveur exposé, des
		// connexions qui n'aboutissent pas sont le bruit de fond normal
		// d'Internet. En faire un avertissement noierait les vrais.
		logs.Write_LogCodeMeta("INFO", logs.CodeNone, fmt.Sprintf(
			"ducky: session %s fermée depuis %s après %s d'inactivité (poignée de main jamais terminée)",
			stale.Status, stale.RemoteAddr, stale.Idle.Round(time.Second)), meta)
		return
	}

	logs.Write_LogCodeMeta("WARNING", logs.CodeNone, fmt.Sprintf(
		"ducky: session authentifiée de %s fermée après %s d'inactivité",
		stale.ClientSoftwareID, stale.Idle.Round(time.Second)), meta)

	if err := db.DeleteDidLogin(db.GetDatabase(), stale.Username, stale.ClientSoftwareID); err != nil {
		logs.Write_LogCodeMeta("ERROR", logs.CodeNone,
			"Error deleting session for "+stale.ClientSoftwareID+": "+err.Error(), meta)
		return
	}
	logs.Write_LogCodeMeta("INFO", logs.CodeNone,
		"Server "+stale.ClientSoftwareID+" is offline and removed from online list", meta)
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

// removeOfflineServer et CheckClientOnline ont été remplacées par
// dropStaleSession, appelée depuis verifyServersOnline.
//
// Elles ne sont pas conservées « au cas où » : leur logique d'expiration
// faisait double emploi avec celle de StaleSessions, et deux règles qui
// décident de fermer une connexion finissent toujours par diverger — celle qui
// n'est plus appelée cessant d'être mise à jour sans que rien ne le signale.

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
