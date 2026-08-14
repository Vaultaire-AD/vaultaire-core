package sshauth

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"net"
	"strings"
	"vaultaire_client/pamstate"
	localusermanagement "vaultaire_client/tools/local_user_management"
	"vaultaire_client/tools/sshreq"
)

func SSH_Auth_Manager(trames_content storage.Trames_struct_client, conn net.Conn) string {
	message := ""

	// On switch sur le sous-ordre (Message_Order[1]) de la catégorie 03 (SSH)
	switch trames_content.Message_Order[1] {

	case "02": // RÉUSSITE : Le serveur envoie les clés (Anciennement 03_02 dans tes logs)
		// Découpage du content : [0]username, [1]isAdmin, puis une ligne
		// « groups:… » facultative, puis les clés jusqu'à la fin.
		lines := strings.Split(strings.TrimSpace(trames_content.Content), "\n")

		if len(lines) < 2 {
			logs.Write_log("ERROR", "Trame SSH 03_02 invalide : contenu incomplet")
			return ""
		}

		sshUser := lines[0]
		isAdmin := (lines[1] == "true")
		groupes, reste := extraireGroupes(lines[2:])
		pubKeys := strings.Join(reste, "\n")

		// 🔥 ACTION SYSTÈME : On crée le user et on pose les clés
		err := localusermanagement.ProvisionVaultaireUser(sshUser, isAdmin, pubKeys)

		// Les APPARTENANCES DE GROUPE, alignées sur ce que le serveur vient de
		// dire. Rafraîchies à chaque connexion, donc sans cache ni cadence.
		//
		// APRÈS le provisionnement : le compte doit exister avant qu'on puisse
		// l'inscrire quelque part.
		//
		// Un échec ici n'annule PAS la connexion. Le mot de passe est vérifié, le
		// droit d'accès à la machine aussi : refuser la session parce qu'une
		// appartenance n'a pas pu être posée serait disproportionné, et laisserait
		// l'utilisateur dehors pour un problème qui ne le concerne pas.
		if err == nil {
			if poses, errG := localusermanagement.AppliquerGroupesUtilisateur(sshUser, groupes); errG != nil {
				logs.Write_log("WARNING", fmt.Sprintf(
					"Groupes de %s non appliqués : %v", sshUser, errG))
			} else if len(poses) < len(groupes) {
				// Le dire : la différence vient de groupes absents de la machine,
				// et c'est exactement ce qu'on cherchera si un droit manque.
				logs.Write_log("INFO", fmt.Sprintf(
					"%s : %d groupe(s) posé(s) sur %d annoncé(s) — les autres n'existent pas "+
						"localement", sshUser, len(poses), len(groupes)))

				// Et le corriger. C'est le seul moment où l'écart entre la liste
				// du domaine et l'état de la machine est VISIBLE et a une
				// conséquence immédiate : un utilisateur ouvre sa session sans
				// les droits qu'il devrait avoir.
				//
				// La demande est asynchrone et ne retarde pas cette session-ci —
				// elle ne peut plus être réparée, la réponse arriverait trop
				// tard. Elle répare la suivante.
				DemanderSynchro()
			}
		}

		// 🔥 Transmission au binaire en attente via le channel
		if respChan, ok := sshreq.Pop(sshUser); ok {
			if err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("Erreur lors de la création de l'utilisateur %s : %v", sshUser, err))
				return ""
			} else {
				logs.Write_log("INFO", fmt.Sprintf("Utilisateur %s provisionné avec succès (Admin: %t)", sshUser, isAdmin))
			}

			// Les GPO de scope user NE sont PAS appliquées ici : cette fonction
			// tourne dans la goroutine qui lit la connexion, et y attendre une
			// réponse du serveur bloquerait la lecture de cette même réponse.
			// Le cycle est lancé depuis le gestionnaire PAM, juste avant de
			// rendre le résultat au module — même ordonnancement, sans blocage
			// du lecteur (voir pam_communication/PAM_Handler.go).
			//
			// Le VERDICT est posé explicitement. Sans lui, l'acceptation se
			// déduisait de l'absence d'information — voir pamstate.AuthResult.
			result := pamstate.AuthResult{
				Type:    "AUTH",
				Accepte: true,
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

		// Un REFUS EXPLICITE, et non plus une simple fermeture du canal.
		//
		// La fermeture seule débloquait bien l'attente, mais elle y déposait le
		// ZÉRO du type — indistinguable d'une réponse pour qui lit sans le
		// second retour. C'est exactement ce que faisait le gestionnaire PAM :
		// un mot de passe refusé par le serveur devenait un « success » rendu à
		// sshd, et /etc/shadow était réécrit avec le mot de passe essayé.
		//
		// Le canal est tamponné à 1 : l'envoi n'attend personne. La fermeture
		// suit, pour qu'un lecteur qui arriverait après l'envoi ne reste pas
		// bloqué — il lira le refus, puis le canal fermé.
		if respChan, ok := sshreq.Pop(sshUser); ok {
			respChan <- pamstate.AuthResult{Type: "AUTH", Accepte: false}
			close(respChan)
		}
	case "05":
		// 03_05 portait le sel et le nonce du défi d'authentification. Le défi a
		// été supprimé : le serveur ne distribue plus le sel, et l'agent ne le
		// demande plus.
		//
		// La branche est conservée pour NOMMER le cas plutôt que de le laisser
		// tomber dans le `default`, qui n'écrit qu'en DEBUG. Recevoir cette trame
		// signifie que le serveur d'en face est resté à l'ancienne version, et
		// c'est exactement ce qu'un administrateur doit lire dans le journal
		// quand les connexions échouent après une mise à jour partielle du parc.
		logs.Write_log("WARNING",
			"Trame 03_05 reçue : le serveur central utilise l'ancienne authentification par défi. "+
				"Mettre à jour vaultaire_serveur.")
	case "07":
		SSH_Handle_Fetch_Pubkey(trames_content)
	case "09":
		HandleGroupSync(trames_content.Content)
	case "10":
		HandleGroupSyncRefus(trames_content.Content)
	default:
		logs.Write_log("DEBUG", "Sous-ordre SSH 03_"+trames_content.Message_Order[1]+" non géré")
	}

	return message
}

// PrefixeGroupes ouvre la ligne des groupes dans la réponse 03_02.
//
// La même chaîne que côté serveur. Les deux vivent dans des modules Go distincts
// — l'agent n'importe pas le serveur — et rien ne peut donc les tenir liées à la
// compilation. Les faire diverger d'un caractère ferait prendre la ligne pour une
// clé publique, en silence : elle atterrirait dans authorized_keys, où sshd
// l'ignorerait sans rien dire, et les appartenances ne seraient jamais posées.
const PrefixeGroupes = "groups:"

// extraireGroupes sépare la ligne des groupes des clés publiques.
//
// # Pourquoi la ligne est reconnue et non comptée
//
// Les clés occupent « tout le reste » du contenu : il n'existait aucune position
// libre après elles. La ligne des groupes se place donc AVANT, et se reconnaît à
// son préfixe plutôt qu'à son rang.
//
// Compter les lignes aurait lié l'agent à une version précise du serveur : un
// serveur qui n'envoie pas encore les groupes décalerait tout, et la première clé
// serait lue comme une liste de groupes. Ici, son absence est simplement un
// contenu sans groupes.
//
// # Le sens de la compatibilité
//
// Cet agent fonctionne avec un serveur qui n'envoie pas la ligne : il n'applique
// alors aucune appartenance, ce qui est l'ancien comportement.
//
// L'INVERSE ne tient pas, et c'est assumé : un agent resté à l'ancienne version
// prendra la ligne pour une clé et l'écrira dans authorized_keys, où sshd
// l'ignorera comme une entrée malformée. Le fichier est réécrit à chaque
// connexion, donc l'artefact disparaît dès la mise à jour de l'agent. Ce chemin a
// déjà une contrainte de version du même ordre — voir la trame 03_04, qui répond
// « obsolete client, update required ».
func extraireGroupes(lignes []string) (groupes []string, reste []string) {
	for i, l := range lignes {
		if !strings.HasPrefix(l, PrefixeGroupes) {
			continue
		}
		liste := strings.TrimPrefix(l, PrefixeGroupes)
		for _, g := range strings.Split(liste, ",") {
			if g = strings.TrimSpace(g); g != "" {
				groupes = append(groupes, g)
			}
		}
		// La ligne est RETIRÉE du reste : la laisser la ferait écrire dans
		// authorized_keys par le provisionnement, ce que la reconnaissance existe
		// précisément pour éviter.
		reste = append(append([]string{}, lignes[:i]...), lignes[i+1:]...)
		return groupes, reste
	}
	return nil, lignes
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
	case respChan <- pamstate.AuthResult{Type: "FETCH", Accepte: true, SSHKeys: sshKeys}:
		logs.Write_log("INFO", fmt.Sprintf("Cles publiques 03_07 transmises au channel pour %s", sshUser))
	default:
		logs.Write_log("WARNING", "Channel réponse SSH plein pour "+sshUser)
	}
}
