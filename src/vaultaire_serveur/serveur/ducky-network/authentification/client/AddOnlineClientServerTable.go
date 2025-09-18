package client

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"net"
)

// This function should be called when a new client connects
func addOnlineServerToTable(username string, clientsoftwareId string, sessionIntegritykey string, conn net.Conn) {
	logs.Write_Log("INFO", "Adding a new server to the online_local list : "+clientsoftwareId+" with username: "+username)
	storage.Serveur_Online = append(storage.Serveur_Online, storage.Is_Serveur_Online{
		Client_ID:           clientsoftwareId,
		Username:            username,
		Conn:                conn,
		Failed_Time:         0,
		SessionIntegritykey: sessionIntegritykey,
	})
	logs.Write_Log("INFO", "Add a new server to the online_local list : "+clientsoftwareId)
}
