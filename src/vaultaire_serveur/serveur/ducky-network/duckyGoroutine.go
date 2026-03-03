package duckynetwork

import (
	db "vaultaire/serveur/database"
	"vaultaire/serveur/ducky-network/sendmessage"
	tm "vaultaire/serveur/ducky-network/trames_manager"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"time"
)

//
// --- Connexions client ---
//

// handleConnection gère une nouvelle connexion client.
func handleConnection(duckysession *storage.DuckySession) {
	defer closeConnection(duckysession)

	logs.Write_Log("INFO", "New connection established: "+duckysession.Conn.RemoteAddr().String())

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

	messageSize := tm.Read_Message_Size(duckysession.Conn, headerSize)
	tm.MessageReader(duckysession, messageSize)
	return true
}

// closeConnection ferme proprement une connexion et log si erreur.
func closeConnection(duckysession *storage.DuckySession) {
	if err := duckysession.Conn.Close(); err != nil {
		logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
	}
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

// verifyServersOnline parcourt la liste des serveurs et vérifie leur état.
func verifyServersOnline() {
	for i := 0; i < len(storage.Serveur_Online); {
		serveur := storage.Serveur_Online[i]
		if !pingServer(serveur) {
			removeOfflineServer(i, serveur)
			continue // ne pas incrémenter car la slice a bougé
		}
		i++
	}
}

// pingServer envoie un message heartbeat à un serveur et retourne true si OK.
func pingServer(serveur storage.Is_Serveur_Online) bool {
	content := "02_11\nserveur_central\n" + serveur.SessionIntegritykey + "\nclient_giveinformation"
	err := sendmessage.SendMessage(content, serveur.Client_ID, serveur.Duckysession)
	if err != nil {
		logs.Write_Log("ERROR", "Error sending heartbeat to "+serveur.Client_ID+": "+err.Error())
		return false
	}
	return true
}

// removeOfflineServer supprime un serveur offline de la mémoire + DB.
func removeOfflineServer(index int, serveur storage.Is_Serveur_Online) {
	// supprimer de la slice
	storage.Serveur_Online = append(storage.Serveur_Online[:index], storage.Serveur_Online[index+1:]...)

	// supprimer de la DB
	err := db.DeleteDidLogin(db.GetDatabase(), serveur.Username, serveur.Client_ID)
	if err != nil {
		logs.Write_Log("ERROR", "Error deleting session for "+serveur.Client_ID+": "+err.Error())
	} else {
		logs.Write_Log("INFO", "Server "+serveur.Client_ID+" is offline and removed from online list")
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
