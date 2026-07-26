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
		// Format Content: "vaultaire\n<username>\n<salt>\n<nonce>"
		lines := strings.Split(strings.TrimSpace(trames_content.Content), "\n")

		if len(lines) < 4 {
			logs.Write_log("ERROR", "Trame 03_05 malformee, champs manquants")
		}

		sshrequser := lines[1] // le vrai username, pas "vaultaire"
		salt := lines[2]
		nonce := lines[3]
		if respChan, ok := sshreq.Pop(sshrequser); ok {
			select {
			case respChan <- storage.AuthResult{Type: "SALT", Salt: salt, Nonce: nonce, IsAdmin: false}:
				logs.Write_log("INFO", fmt.Sprintf("Salt/Nonce 03_05 transmis au channel pour %s", sshrequser))
			default:
			}
		} else {
			logs.Write_log("WARNING", fmt.Sprintf("Réception 03_05 pour %s mais aucun channel en attente", sshrequser))
		}
	case "07":
		SSH_Handle_Fetch_Pubkey(trames_content)
	default:
		logs.Write_log("DEBUG", "Sous-ordre SSH 03_"+trames_content.Message_Order[1]+" non géré")
	}

	return message
}

func SSH_Handle_Fetch_Pubkey(trames_content storage.Trames_struct_client) {
	// Format Content attendu: "vaultaire\n\n<username>\n<clé1>\n<clé2>..."
	// (il y a une ligne vide en position 1 à cause du "\n"+"\n" dans SSH_SEND_Fetch_Pubkey)
	lines := strings.Split(strings.TrimSpace(trames_content.Content), "\n")

	if len(lines) < 3 {
		logs.Write_log("ERROR", "Trame 03_07 malformee, champs manquants")
		return
	}

	sshUser := lines[2]
	sshKeys := strings.Join(lines[3:], "\n")

	respChan, ok := sshreq.Pop(sshUser)
	if !ok {
		logs.Write_log("WARNING", fmt.Sprintf("Réception 03_07 pour %s mais aucun channel en attente", sshUser))
		return
	}

	select {
	case respChan <- storage.AuthResult{Type: "FETCH", SSHKeys: sshKeys}:
		logs.Write_log("INFO", fmt.Sprintf("Cles publiques 03_07 transmises au channel pour %s", sshUser))
	default:
		logs.Write_log("WARNING", "Channel réponse SSH plein pour "+sshUser)
	}
}
