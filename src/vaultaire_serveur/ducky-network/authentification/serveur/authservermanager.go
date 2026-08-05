package serveur

import (
	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/sessionmgr"
)

// Serveur_Auth_Manager manages the authentication requests from servers.
// It processes different message types based on the second element of the Message_Order slice.
// It handles authentication requests and returns a string message indicating the result of the operation.
// This function is part of the server authentication management system and is used to maintain session integrity and security.
// It is called when a server requests authentication, ensuring that the server is properly authenticated and logged.
func Serveur_Auth_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "01":
		oldSessionID := duckysession.SessionID

		sessionIntegritykey, err := sessionmgr.Sessions.GenerateIntegrityKey()
		if err != nil {
			message = "error"
			logs.Write_LogCodeMeta("ERROR", logs.CodeNone,
				"Error during initial handshake: "+err.Error(), logs.WithMeta(oldSessionID, trames_content.Username))
			err := duckysession.Conn.Close()
			if err != nil {
				logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
			}
			break
		}
		duckysession.SessionKey = []byte(sessionIntegritykey)

		// À partir d'ici, SessionID = SessionIntegritykey réel : le même
		// identifiant sert de clé de log et de clé réseau (voir
		// sessionmgr.Manager.Rekey). On attache aussi l'identité annoncée par
		// le client (pas encore prouvée, mais utile pour tracer une tentative
		// même si elle échoue plus loin dans le login).
		duckysession.SessionID = sessionIntegritykey
		sessionmgr.Sessions.Rekey(oldSessionID, sessionIntegritykey)
		sessionmgr.Sessions.SetIdentity(sessionIntegritykey, trames_content.Username, trames_content.ClientSoftwareID)

		// Fige la machine pour toute la durée de la connexion. La réponse 01_02
		// est chiffrée avec la clé publique de cet identifiant et transporte la
		// clé de session : seul son vrai propriétaire pourra lire la suite.
		// Toutes les trames ultérieures seront comparées à cette valeur (voir
		// tramesmanager.Split_Action).
		duckysession.BoundClientSoftwareID = trames_content.ClientSoftwareID

		// Le TYPE de programme est lu ici, une seule fois, et figé comme
		// l'identifiant. Il décide de ce que la session pourra émettre — voir
		// core/clienttype et tramesmanager.Split_Action.
		//
		// Une lecture qui échoue laisse BoundClientType vide, et un type vide
		// n'émet rien : la session est ouverte mais stérile. C'est le bon sens
		// de l'échec — une base injoignable ne doit pas ouvrir le protocole,
		// elle doit le fermer.
		if clientType, err := dbclients.Get_Client_Type(database.GetDatabase(), trames_content.ClientSoftwareID); err != nil {
			logs.Write_LogCodeMeta("WARNING", logs.CodeNone,
				"type de client illisible pour "+trames_content.ClientSoftwareID+" : "+err.Error(),
				logs.WithMeta(sessionIntegritykey, trames_content.Username))
		} else {
			duckysession.BoundClientType = clientType
		}
		// Amorce le suivi de l'ordre des trames pour la suite de la session
		// (remplace le seed fait par l'ancien sync.AddConnectionToMap).
		sessionmgr.Sessions.SeedTrame(sessionIntegritykey, "01_01")

		message = Prove_Identity(trames_content.Content, sessionIntegritykey)

	case "03":
		// Enrôlement d'un client service. Arrive AVANT toute session : le
		// client n'existe pas encore, donc ni identifiant ni type à figer.
		message = HandleEnrollment(trames_content, duckysession)
	}
	return message
}
