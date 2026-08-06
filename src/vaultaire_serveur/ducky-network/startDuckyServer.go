package duckynetwork

import (
	"net"
	"vaultaire/core/logs"
	"vaultaire/core/netguard"
	"vaultaire/core/storage"
	keymanagement "vaultaire/ducky-network/key_management"
	"vaultaire/ducky-network/sessionmgr"
)

// --- Initialisation globale ---

func initializeServer() {
	// Le registre de sessions (sessionmgr.Sessions) s'auto-initialise à
	// l'import (var package-level), plus besoin d'un init explicite ici
	// comme pour l'ancienne sync.Map.
	go clearSession()
	go checkServeurOnline()
}

// --- Gestion des clés ---

func generateKeys() error {
	if err := keymanagement.Generate_Serveur_Key_Pair(); err != nil {
		logs.Write_Log("CRITICAL", "Error generating server key pair: "+err.Error())
		return err
	}
	if err := keymanagement.Generate_SSH_Key_For_Login_Client(); err != nil {
		logs.Write_Log("CRITICAL", "Error generating SSH key for login client: "+err.Error())
		return err
	}
	return nil
}

// --- Mise en place du listener ---

func createListener() (net.Listener, error) {
	listener, err := net.Listen("tcp", ":"+storage.ServeurLisetenPort)
	if err != nil {
		logs.Write_Log("CRITICAL", "Error listening on port "+storage.ServeurLisetenPort+": "+err.Error())
		return nil, err
	}
	return listener, nil
}

// duckyLimiter borne les connexions simultanées sur le port Ducky.
//
// 2000 au total : très au-dessus d'un parc réaliste — un agent tient UNE
// connexion machine — et bien en dessous de la limite de descripteurs d'un
// processus, qui est le vrai mur.
//
// 20 par adresse : un poste ouvre une connexion machine et une par session
// utilisateur locale. Vingt laisse une marge confortable, et arrête net une
// source qui en ouvre des milliers.
//
// Une machine NAT derrière laquelle vivent plus de vingt postes se ferait
// refuser : c'est le cas à surveiller à la mise en service, et la raison pour
// laquelle le refus est journalisé avec l'adresse et le motif.
var duckyLimiter = netguard.NewLimiter("ducky", 2000, 20)

// --- Boucle principale ---

func acceptConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			logs.Write_LogCode("WARNING", logs.CodeNetConnection, "ducky: error accepting new connection: "+err.Error())
			continue
		}
		duckysession := &storage.DuckySession{
			Conn:   conn,
			IsSafe: false,
			// SessionID est prêt dès l'accept(), avant la moindre trame lue :
			// la connexion est traçable dans les logs depuis l'instant zéro.
			// Il sera remplacé par le SessionIntegritykey réel une fois la
			// poignée de main initiale terminée (voir authservermanager.go).
			SessionID: sessionmgr.NewSessionID(),
		}
		// Plafond de connexions, AVANT d'enregistrer quoi que ce soit.
		//
		// Une connexion coûte un descripteur, une goroutine et une entrée de
		// registre — et rien de tout cela ne demande d'identifiant. Le balayage
		// périodique nettoie les inactives, mais il tourne toutes les deux minutes :
		// entre deux passages, la fenêtre reste ouverte.
		//
		// Le refus est SILENCIEUX côté client : on ferme sans répondre. Répondre
		// donnerait à un attaquant un signal utile — il saurait qu'il a atteint le
		// plafond, donc qu'il en existe un et où il est.
		release, autorisé, motif := duckyLimiter.Acquire(conn)
		if !autorisé {
			logs.Write_LogCode("WARNING", logs.CodeNetConnection,
				"ducky: connexion refusée depuis "+netguard.SourceAddr(conn)+" : "+motif)
			if err := conn.Close(); err != nil {
				logs.Write_Log("DEBUG", "ducky: fermeture après refus : "+err.Error())
			}
			continue
		}

		sessionmgr.Sessions.AddOrUpdate(duckysession.SessionID, conn, sessionmgr.SessionPending, duckysession)
		go func() {
			defer release()
			handleConnection(duckysession)
		}()
	}
}

// --- Point d'entrée ---

func StartDuckyServer() {
	initializeServer()

	if err := generateKeys(); err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeNetKey, "ducky: key generation failed")
		return
	}

	listener, err := createListener()
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeNetConnection, "ducky: listener creation failed")
		return
	}

	logs.Write_Log("INFO", "ducky: server ready and listening on port "+storage.ServeurLisetenPort)

	acceptConnections(listener)
}
