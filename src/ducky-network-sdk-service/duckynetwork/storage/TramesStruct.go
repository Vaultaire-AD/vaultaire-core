package storage

import "net"

type Trames_struct_client struct {
	Message_Order       []string
	Destination_Server  string
	SessionIntegritykey string
	Username            string
	Content             string
}

type Trames_struct struct {
	Message_Order      []string
	Destination_Server string
	Content            string
}

type DuckySession struct {
	SessionID  string
	Conn       net.Conn
	IsSafe     bool
	SessionKey []byte

	// Refus porte le motif du refus d'authentification que le core a opposé
	// à CETTE session (trame 02_07) — TO-DO 159. Vide tant qu'aucun refus
	// n'est arrivé.
	//
	// C'est le signal de fermeture : la boucle de réception s'arrête dès qu'il
	// est posé (tramesmanager.MessageReader rend ErrSessionRefusee), et la
	// boucle de reconnexion s'en sert pour ne pas repartir du délai le plus
	// court. Il est écrit par la goroutine qui lit la connexion et relu après
	// sa fin : aucun verrou n'est nécessaire.
	Refus string
}

// var DuckySessionLive *DuckySession
