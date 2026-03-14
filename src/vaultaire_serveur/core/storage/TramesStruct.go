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
	Conn       net.Conn
	IsSafe     bool
	SessionKey []byte
}
