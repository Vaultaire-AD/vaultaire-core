package sshauth

import (
	"fmt"
	"net"
	"strings"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
)

func SSH_Auth_Manager(trames_content storage.Trames_struct_client, conn net.Conn) string {

	// Vérification du type de message
	if len(trames_content.Message_Order) != 2 ||
		trames_content.Message_Order[0] != "03" ||
		trames_content.Message_Order[1] != "02" {

		logs.Write_Log("ERROR", "SSH_Auth_Manager appelé avec une mauvaise trame")
		return "02_98\nserveur_central\nwrong_handler"
	}

	// Découpage du content
	lines := strings.Split(strings.TrimSpace(trames_content.Content), "\n")

	if len(lines) < 2 {
		logs.Write_Log("ERROR", "Trame SSH 03_02 invalide : contenu incomplet")
		return "02_99\nserveur_central\ninvalid_content"
	}

	sshUser := lines[0]
	pubKeys := lines[1:]

	// Sécurité minimale
	if len(pubKeys) == 0 {
		logs.Write_Log("WARN", "Aucune clé SSH reçue pour l'utilisateur "+sshUser)
	}
	pubKeyStr := strings.Join(pubKeys, "\n")
	// Exemple de traitement : log
	logs.Write_Log(
		"INFO",
		fmt.Sprintf(
			"Réception de %d clés SSH pour l'utilisateur %s",
			len(pubKeys),
			sshUser,
		),
	)

	// 🔥 POINT CRITIQUE 🔥
	// Injection dans le channel attendu par handleCheckRequest
	select {
	case storage.Authentification_SSHpubkey <- pubKeyStr:
		// OK
	default:
		logs.Write_Log("WARN", "Channel Authentification_SSHpubkey bloqué")
	}

	// Aucun retour réseau nécessaire ici
	return ""
}
