package client

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"net"
)

// This function should be called when a new client connects
func addOnlineServerToTable(clientsoftwareId string, sessionIntegritykey string, conn net.Conn) {
	storage.Serveur_Online = append(storage.Serveur_Online, storage.Is_Serveur_Online{
		Client_ID:           clientsoftwareId,
		Conn:                conn,
		Failed_Time:         0,
		SessionIntegritykey: sessionIntegritykey,
	})
	logs.Write_Log("INFO", "Add a new server to the online_local list : "+clientsoftwareId)
}
