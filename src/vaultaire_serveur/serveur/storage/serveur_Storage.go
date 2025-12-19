package storage

import "net"

type Is_Serveur_Online struct {
	Client_ID           string
	Username            string
	Conn                net.Conn
	Failed_Time         int
	SessionIntegritykey string
}

var Serveur_Online []Is_Serveur_Online
