package serveurcommunication

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	sto_session "duckynetworkclient/V1/duckynetwork/storage/stosession"
	br "duckynetworkclient/V1/duckynetwork/trames_manager"
	"fmt"
)

func handleConnection(user string, duckysession *storage.DuckySession) {
	// logs.Write_log("INFO", fmt.Sprintf("Démarrage du gestionnaire de flux pour %s", user))
	defer func() {
		if r := recover(); r != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Panic récupéré dans handleConnection pour %s: %v", user, r))
		}
		duckysession.Conn.Close()
		// On supprime de la map (par SessionID, pas par username) pour que la
		// boucle de check SSH sorte aussi si besoin
		sto_session.SessionsUser.RemoveSession(duckysession.SessionID)
		logs.Write_log("INFO", fmt.Sprintf("Flux terminé pour %s (session id=%s), socket fermé", user, duckysession.SessionID))
	}()

	for {
		// IMPORTANT: Ta fonction Read_Header_Size DOIT retourner une erreur si le socket ferme
		headerSize, err := br.Read_Header_Size(duckysession.Conn)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture du header : %v", err))
			return
		}

		// Si on a lu quelque chose, on rafraîchit le LastSeen pour le cleanupLoop
		sto_session.SessionsUser.Touch(duckysession.SessionID)

		// Read_Header_Size ne rend plus jamais 0 sans erreur : un premier
		// octet autre que 2 est refusé, et la connexion fermée (TO-DO 101).
		messagesize, err := br.Read_Message_Size(duckysession.Conn, headerSize)
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la lecture de la taille du message : %v", err))
			return
		}
		// Un corps lu à moitié laisse le flux à une position inconnue : on
		// ferme, plutôt que de lire la suite comme un en-tête.
		if err := br.MessageReader(duckysession, messagesize); err != nil {
			return
		}
	}
}
