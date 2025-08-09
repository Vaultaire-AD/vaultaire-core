package vaultairegoroutine

import (
	"DUCKY/serveur/command"
	"DUCKY/serveur/database"
	db "DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/sendmessage"
	"DUCKY/serveur/storage"
	br "DUCKY/serveur/trames_manager"
	"fmt"
	"net"
	"os"
	"time"
)

// boucle qui clear la table session de la base de donnéees toute les 60Minutes
func ClearSession() {
	ticker := time.NewTicker(60 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		err := db.CleanUpExpiredSessions(db.GetDatabase())
		if err != nil {
			logs.Write_Log("ERROR", "Error during the clear of the user session "+err.Error())
		}
	}
}

// Démarre le serveur UNIX pour écouter les commandes CLI
func StartUnixSocketServer() {

	os.Remove(storage.SocketPath)

	listener, err := net.Listen("unix", storage.SocketPath)
	if err != nil {
		fmt.Println("Erreur création socket UNIX:", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Println("Serveur en attente de commandes...")

	// Boucle pour accepter les connexions
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Erreur connexion client :", err)
			continue
		}
		go command.HandleClientCLI(conn)
	}
}

// boucle qui tourne pour recevoir les requetes client(utilisateur et services)
func HandleConnection(conn net.Conn) {
	defer conn.Close()
	logs.Write_Log("INFO", "New connection establish :"+conn.RemoteAddr().String())
	for {
		headerSize := br.Read_Header_Size(conn)
		if headerSize != 0 {
			messagesize := br.Read_Message_Size(conn, headerSize)
			br.MessageReader(conn, messagesize)
		}
	}
}

// Check Serveur Online Verifie si le serveur est en ligne toutes les 10 minutes
func CheckServeurOnline() {
	ticker := time.NewTicker(time.Duration(storage.ServerCheckOnlineTimer) * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		for i, serveur := range storage.Serveur_Online {
			content := "02_11\nserveur_central\n" + serveur.SessionIntegritykey + "\nclient_giveinformation"
			err := sendmessage.SendMessage(content, serveur.Client_ID, serveur.Conn)
			if err != nil {
				logs.Write_Log("ERROR", "Error during the send of the message to "+serveur.Client_ID+" : "+err.Error())
				storage.Serveur_Online = append(storage.Serveur_Online[:i], storage.Serveur_Online[i+1:]...)
				database.DeleteDidLogin(db.GetDatabase(), serveur.Client_ID, serveur.Client_ID)
			}
		}
	}
}
