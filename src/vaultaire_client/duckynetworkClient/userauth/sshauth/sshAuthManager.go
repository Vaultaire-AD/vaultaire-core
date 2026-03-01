package sshauth

import (
	"net"
	"strings"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
	"vaultaire_client/tools/sshreq"
)

func SSH_Auth_Manager(trames_content storage.Trames_struct_client, conn net.Conn) string {

	// Vérification du type de message
	if len(trames_content.Message_Order) != 2 ||
		trames_content.Message_Order[0] != "03" ||
		trames_content.Message_Order[1] != "02" {

		logs.Write_log("ERROR", "SSH_Auth_Manager appelé avec une mauvaise trame")
		return "03_98\nserveur_central\nwrong_handler"
	}

	// Découpage du content
	lines := strings.Split(strings.TrimSpace(trames_content.Content), "\n")

	if len(lines) < 2 {
		logs.Write_log("ERROR", "Trame SSH 03_02 invalide : contenu incomplet")
		return "03_99\nserveur_central\ninvalid_content"

	}

	sshUser := lines[0]
	isAdminStr := lines[1]
	pubKeys := lines[2:]
	isAdmin := (isAdminStr == "true")

	// Sécurité minimale
	if len(pubKeys) == 0 {
		logs.Write_log("WARNING", "Aucune clé SSH reçue pour l'utilisateur "+sshUser)
	}
	pubKeyStr := strings.Join(pubKeys, "\n")
	// Exemple de traitement : log

	// 🔥 POINT CRITIQUE 🔥
	respChan, ok := sshreq.Pop(sshUser)

	if ok {
		// Le channel doit maintenant être de type chan storage.AuthResult
		result := storage.AuthResult{
			Keys:    pubKeyStr,
			IsAdmin: isAdmin,
		}
		select {
		case respChan <- result:
			logs.Write_log("INFO", "Clés SSH transmises au demandeur pour "+sshUser)
		default:
			logs.Write_log("WARNING", "Channel réponse SSH plein pour "+sshUser)
		}
	} else {
		logs.Write_log("WARNING", "Aucune requête SSH en attente pour "+sshUser)
	}
	// Aucun retour réseau nécessaire ici
	return ""
}
