package serveurcommunication

import (
	"fmt"
	br "vaultaire_client/duckynetworkClient/trames_manager"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
	sto_session "vaultaire_client/storage/stosession"
)

func handleConnection(user string, duckysession *storage.DuckySession) {
	logs.Write_log("INFO", fmt.Sprintf("Démarrage du gestionnaire de flux pour %s", user))
	defer func() {
		if r := recover(); r != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Panic récupéré dans handleConnection pour %s: %v", user, r))
		}
		duckysession.Conn.Close()
		// On supprime de la map pour que la boucle de check SSH sorte aussi si besoin
		sto_session.SessionsUser.Delete(user)
		logs.Write_log("INFO", fmt.Sprintf("Flux terminé pour %s, socket fermé", user))
	}()

	for {
		// IMPORTANT: Ta fonction Read_Header_Size DOIT retourner une erreur si le socket ferme
		headerSize, err := br.Read_Header_Size(duckysession.Conn)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du header : %v", err))
			return
		}

		// Si on a lu quelque chose, on rafraîchit le LastSeen pour le cleanupLoop
		sto_session.SessionsUser.Touch(user)

		if headerSize != 0 {
			messagesize, err := br.Read_Message_Size(duckysession.Conn, headerSize)
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture de la taille du message : %v", err))
				return
			}
			br.MessageReader(duckysession, messagesize)
		}
	}
}
