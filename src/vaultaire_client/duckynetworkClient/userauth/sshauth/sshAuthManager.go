package sshauth

import (
	"fmt"
	"net"
	"strings"
	"vaultaire_client/logs"
	"vaultaire_client/storage"
	localusermanagement "vaultaire_client/tools/local_user_management"
	"vaultaire_client/tools/sshreq"
)

func SSH_Auth_Manager(trames_content storage.Trames_struct_client, conn net.Conn) string {
	message := ""

	// On switch sur le sous-ordre (Message_Order[1]) de la catégorie 03 (SSH)
	switch trames_content.Message_Order[1] {

	case "02": // RÉUSSITE : Le serveur envoie les clés (Anciennement 03_02 dans tes logs)
		// Découpage du content : [0]username, [1]isAdmin, [2:]clés
		lines := strings.Split(strings.TrimSpace(trames_content.Content), "\n")

		if len(lines) < 2 {
			logs.Write_log("ERROR", "Trame SSH 03_02 invalide : contenu incomplet")
			return ""
		}

		sshUser := lines[0]
		isAdmin := (lines[1] == "true")
		pubKeys := strings.Join(lines[2:], "\n")

		// 🔥 ACTION SYSTÈME : On crée le user et on pose les clés
		err := localusermanagement.ProvisionVaultaireUser(sshUser, isAdmin, pubKeys)

		// 🔥 Transmission au binaire en attente via le channel
		if respChan, ok := sshreq.Pop(sshUser); ok {
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la création de l'utilisateur %s : %v", sshUser, err))
				return ""
			} else {
				logs.Write_log("INFO", fmt.Sprintf("Utilisateur %s provisionné avec succès (Admin: %t)", sshUser, isAdmin))
			}
			result := storage.AuthResult{
				IsAdmin: isAdmin,
			}
			select {
			case respChan <- result:
				logs.Write_log("INFO", "Clés SSH transmises au demandeur pour "+sshUser)
			default:
				logs.Write_log("WARNING", "Channel réponse SSH plein pour "+sshUser)
			}
		} else {
			logs.Write_log("WARNING", "Aucune requête SSH locale en attente pour "+sshUser)
		}

	case "03": // ERREUR : Le serveur refuse l'accès ou l'utilisateur n'existe pas
		lines := strings.Split(strings.TrimSpace(trames_content.Content), "\n")
		sshUser := "unknown"
		if len(lines) > 0 {
			sshUser = lines[0]
		}

		logs.Write_log("ERROR", "Le serveur central a refusé l'accès SSH pour : "+sshUser)

		// On débloque le channel avec un résultat vide pour éviter le timeout infini
		if respChan, ok := sshreq.Pop(sshUser); ok {
			close(respChan)
		}
	case "05": // RÉUSSITE FETCH BRUT (03_05)
		// Format: [0]"vaultaire", [1:]clés... (Le user n'est pas dans le content !)
		lines := strings.Split(strings.TrimSpace(trames_content.Content), "\n")

		// On récupère les clés (tout ce qui suit "vaultaire")
		pubKeyStr := ""
		if len(lines) > 1 {
			pubKeyStr = strings.Join(lines[1:], "\n")
		}
		sshrequser := lines[0] // "vaultaire" dans ce cas, pas d'info user dans le content
		// 💡 PROBLEME : On n'a pas le nom de l'utilisateur dans la trame 05.
		// On doit utiliser PopAny() ou passer par un index de session si tu as plusieurs requêtes.
		// Si c'est du One-Shot, on récupère la dernière requête en attente.
		if respChan, ok := sshreq.Pop(sshrequser); ok {
			select {
			case respChan <- storage.AuthResult{Keys: pubKeyStr, IsAdmin: false}:
				logs.Write_log("INFO", "Clés 03_05 (Brut) transmises au channel")
			default:
			}
		} else {
			logs.Write_log("WARNING", "Réception 03_05 mais aucun channel en attente")
		}

	case "98", "99": // ERREURS PROTOCOLE
		logs.Write_log("ERROR", fmt.Sprintf("Erreur protocole SSH reçue : 03_%s | Content: %s",
			trames_content.Message_Order[1], trames_content.Content))

	default:
		logs.Write_log("DEBUG", "Sous-ordre SSH 03_"+trames_content.Message_Order[1]+" non géré")
	}

	return message
}
