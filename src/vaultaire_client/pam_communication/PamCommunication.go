package pamcommunication

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"vaultaire_client/logs"
	"vaultaire_client/storage"
)

func isValidUserInput(input string) bool {
	if input == "" {
		return false
	}
	validInputPattern := `^[a-zA-Z0-9._@-]+$`
	re := regexp.MustCompile(validInputPattern)
	return re.MatchString(input)
}

func handleUnixSocketConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Error closing connection: %v", err))
		}
	}()
	// Contrôle d'identité AVANT de lire quoi que ce soit.
	//
	// Le premier octet lu vient d'un appelant dont on ne sait encore rien. Les
	// permissions du socket devraient suffire ; ce contrôle existe pour le jour
	// où elles ne suffisent pas — répertoire recréé à la main, image déployée
	// avec le mauvais mode. Le mot de passe en clair de chaque connexion passe
	// par ici.
	root, qui, err := peerIsRoot(conn)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf(
			"socket PAM : identité de l'appelant illisible, connexion fermée : %v", err))
		return
	}
	if !root {
		connexionsRefusees.Add(1)
		// SECURITY et non WARNING : personne d'autre que root n'a de raison
		// légitime d'ouvrir ce canal. Une seule occurrence mérite d'être vue.
		logs.Write_log("CRITICAL", fmt.Sprintf(
			"socket PAM : connexion refusée, appelant non privilégié (%s)", qui))
		return
	}

	var message map[string]json.RawMessage
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&message); err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("Erreur de decodage du message JSON: %v", err))
		return
	}

	// Routage : 'auth' et 'check' utilisent la même fonction générique
	if auth, exists := message["auth"]; exists {
		processPamRequest(conn, "AUTH", string(auth))

	} else if check, exists := message["check"]; exists {
		processPamRequest(conn, "CHECK", string(check))

	} else if closeMsg, exists := message["close"]; exists {
		handleCloseRequest(conn, string(closeMsg))

	} else {
		log.Printf("Commande inconnue reçue: %v", message)
	}
}

// UnixSocketServer ouvre le canal PAM à l'emplacement configuré.
func UnixSocketServer() {
	serveSocket(storage.SocketPath)
}

// serveSocket fait le travail, sur un chemin EXPLICITE.
//
// Le chemin est un paramètre et non une lecture de la variable globale : cette
// goroutine ne s'arrête jamais, et lire une globale que les tests déplacent la
// ferait courir contre eux — signalé par -race. En production la valeur ne
// bouge pas, mais un code qui n'est correct que parce que personne ne le
// sollicite reste un code faux.
func serveSocket(chemin string) {
	// Le répertoire d'abord, en 0700 : c'est LA protection. Même si le socket
	// disparaît, un non-root ne peut rien créer à sa place.
	if err := ensureSocketDir(filepath.Dir(chemin)); err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("socket PAM : %v", err))
		return
	}

	// Nettoyage de l'ancien emplacement dans /tmp.
	//
	// Un socket laissé là par une version précédente reste un point de collecte
	// de mots de passe tant qu'un module PAM non mis à jour s'y connecte. On le
	// retire, sans traiter l'échec comme fatal : le fichier peut appartenir à
	// quelqu'un d'autre, ce qui est précisément le scénario d'attaque et mérite
	// d'être signalé plutôt que d'empêcher l'agent de démarrer.
	if _, err := os.Stat(storage.LegacySocketPath); err == nil {
		if err := os.Remove(storage.LegacySocketPath); err != nil {
			logs.Write_log("CRITICAL", fmt.Sprintf(
				"socket PAM : ancien socket %s non supprimé (%v) — vérifiez à qui il appartient",
				storage.LegacySocketPath, err))
		} else {
			logs.Write_log("WARNING", "socket PAM : ancien socket "+storage.LegacySocketPath+" supprimé")
		}
	}

	if err := os.RemoveAll(chemin); err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("Error removing existing socket file: %v", err))
	}

	// umask pendant le bind : le socket naît en 0600, il n'existe jamais avec un
	// mode plus large.
	//
	// Un Chmod APRÈS net.Listen laisserait une fenêtre — courte, mais un socket
	// d'authentification accessible pendant quelques microsecondes au démarrage
	// reste un socket accessible.
	ancienMasque := syscall.Umask(0o177)
	ln, err := net.Listen("unix", chemin)
	syscall.Umask(ancienMasque)
	if err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("Error creating Unix socket: %v", err))
		return
	}
	defer func() {
		if err := ln.Close(); err != nil {
			logs.Write_log("CRITICAL", fmt.Sprintf("Error closing Unix socket: %v", err))
		}
	}()

	// Ceinture et bretelles : si l'umask n'a pas produit l'effet attendu (montage
	// exotique, noyau ancien), on force le mode et on vérifie.
	if err := os.Chmod(chemin, 0o600); err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("socket PAM : mode non appliqué : %v", err))
		return
	}
	if info, err := os.Stat(chemin); err == nil && info.Mode().Perm() != 0o600 {
		logs.Write_log("CRITICAL", fmt.Sprintf(
			"socket PAM : mode %o inattendu, arrêt — le canal ne sera pas ouvert", info.Mode().Perm()))
		return
	}

	logs.Write_log("INFO", fmt.Sprintf("Server listening on Unix socket: %s", chemin))

	for {
		conn, err := ln.Accept()
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("Error accepting connection: %v", err))
			continue
		}
		logs.Go("session PAM", func() { handleUnixSocketConnection(conn) })
	}
}
