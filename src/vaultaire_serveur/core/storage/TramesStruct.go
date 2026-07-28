package storage

import "net"

type Trames_struct_client struct {
	Message_Order       []string
	Destination_Server  string
	SessionIntegritykey string
	Username            string
	Domain              string
	ClientSoftwareID    string
	Content             string
}

type Trames_struct struct {
	Message_Order      []string
	Destination_Server string
	Content            string
}

type DuckySession struct {
	// SessionID identifie cette connexion de façon unique. Il est généré à
	// l'accept() (voir sessionmgr.NewSessionID), puis aligné sur le
	// SessionIntegritykey réel une fois la poignée de main initiale terminée
	// (voir sessionmgr.Manager.Rekey), pour rester grep-able de façon
	// interchangeable entre les logs et le protocole réseau.
	SessionID  string
	Conn       net.Conn
	IsSafe     bool
	SessionKey []byte
}
