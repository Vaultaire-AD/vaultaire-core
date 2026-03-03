package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"
	"vaultaire_client/duckynetworkClient/sendmessage"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
	sto_session "vaultaire_client/storage/stosession"
)

type CloseRequest struct {
	User   string `json:"user"`
	Action string `json:"action"`
}

func handleCloseRequest(conn net.Conn, payload string) {
	// Fermeture du socket local (celui qui a envoyé la requête JSON)
	defer conn.Close()

	var closeReq CloseRequest
	err := json.Unmarshal([]byte(payload), &closeReq)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur de décodage JSON close: %v", err))
		return
	}

	if closeReq.Action != "S_close" {
		logs.Write_log("ERROR", fmt.Sprintf("Action invalide dans close: %s", closeReq.Action))
		return
	}

	logs.Write_log("INFO", fmt.Sprintf("Demande de fermeture de session reçue pour: %s", closeReq.User))

	// Récupération de la session ACTIVE via ton nouveau système
	duckysession, exist := sto_session.SessionsUser.GetDuckySession(closeReq.User)

	if !exist {
		logs.Write_log("WARNING", fmt.Sprintf("Tentative de fermeture pour %s mais aucune connexion active trouvée", closeReq.User))
		return
	}

	// 1. Préparer et envoyer le message de clôture au serveur central
	// On utilise la session récupérée dynamiquement
	message := fmt.Sprintf("02_05\nserveur_central\n%s\n%s\nclose", closeReq.User, storage.Computeur_ID)

	// SendMessage doit utiliser la connexion présente dans duckysession

	sendmessage.SendMessage(message, duckysession)

	// 2. NETTOYAGE CRITIQUE : on supprime des deux côtés
	sto_session.SessionsUser.Delete(closeReq.User) // Supprime du manager de sessions (et ferme le socket TCP)

	logs.Write_log("INFO", fmt.Sprintf("Session %s proprement fermée et retirée des registres", closeReq.User))
}
