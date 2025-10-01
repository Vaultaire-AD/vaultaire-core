package command

import (
	commandadd "DUCKY/serveur/command/command_add"
	commandcreate "DUCKY/serveur/command/command_create"
	commanddelete "DUCKY/serveur/command/command_delete"
	commanddns "DUCKY/serveur/command/command_dns"
	commandeyes "DUCKY/serveur/command/command_eyes"
	commandget "DUCKY/serveur/command/command_get"
	commandremove "DUCKY/serveur/command/command_remove"
	commandstatus "DUCKY/serveur/command/command_status"
	commandupdate "DUCKY/serveur/command/command_update"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
	"net"
	"strings"
)

// case "get", "eyes", "status":
// 	return "api_read_permission", nil
// case "add", "remove", "update", "dns":
// 	return "api_write_permission", nil
// case "create", "clear", "delete":
// 	return "api_admin_permission", nil

// Fonction qui exécute une commande et retourne le résultat
func ExecuteCommand(input string, sender_Username string) string {
	// Nettoyer et diviser la commande
	print("Input: ", input)
	command_list := SplitArgsPreserveBlocks(input)
	if len(command_list) == 0 {
		return "Erreur : commande vide."
	}
	if len(command_list) == 1 {
		command_list = append(command_list, "-h")
	}

	// Récupérer la commande principale et les arguments
	command := command_list[0]
	args := command_list[1:]

	// Buffer pour stocker la réponse
	var response string
	// Exécuter la commande
	switch command {
	case "status":
		response = commandstatus.Status_Command(args)
	case "clear":
		sender_groupsIDs, action, err := permission.PrePermissionCheck(sender_Username, "api_write_permission")
		if err != nil {
			return fmt.Sprintf("Erreur de permission : %v", err)
		}
		isactionlegitimate, response := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, []string{"*"})
		if !isactionlegitimate {
			logs.Write_Log("WARNING", fmt.Sprintf("Permission refusée pour l'utilisateur %s sur l'action %s : %s", sender_Username, action, response))
			return fmt.Sprintf("Permission refusée : %s", response)
		}
		err = database.CleanUpExpiredSessions(database.DB)
		if err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors du nettoyage des sessions expirées : %v", err))
			response = "Erreur lors du nettoyage des sessions expirées."
			break
		}
		response = "Sessions expirées nettoyées."
	case "create":
		sender_groupsIDs, action, err := permission.PrePermissionCheck(sender_Username, "api_write_permission")
		if err != nil {
			return fmt.Sprintf("Erreur de permission : %v", err)
		}

		response = commandcreate.Create_Command(args, sender_groupsIDs, action, sender_Username)
	case "get":
		sender_groupsIDs, action, err := permission.PrePermissionCheck(sender_Username, "api_read_permission")
		if err != nil {
			return fmt.Sprintf("Erreur de permission : %v", err)
		}
		response = commandget.Get_Command(args, sender_groupsIDs, action, sender_Username)
	case "add":
		response = commandadd.Add_Command(args)
	case "remove":
		response = commandremove.Remove_Command(args)
	case "delete":
		response = commanddelete.Delete_Command(args)
	case "update":
		response = commandupdate.Update_Command(args)
	case "eyes":
		response = commandeyes.Eyes_Command(args)
	case "dns":
		response = commanddns.DNS_Command(args)
	case "setup":
	case "help":
		response = "Liste des commandes disponibles :\n" +
			"  create [OPTIONS] : crée une nouvelle entrée.\n" +
			"  status [OPTIONS] : Vérifie l'état du serveur.\n" +
			"  clear [OPTIONS]  : Nettoie les sessions.\n" +
			"  help             : Affiche cette aide."
	default:
		response = fmt.Sprintf("Commande inconnue : %s. Tapez 'help' pour plus d'informations.", command)
	}

	return response
}

// Fonction qui gère la communication avec les clients via le socket UNIX
func HandleClientCLI(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
		}
	}()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Erreur lecture commande :", err)
		return
	}

	// Exécuter la commande et récupérer la réponse
	command := strings.TrimSpace(string(buf[:n]))
	result := ExecuteCommand(command, "vaultaire")

	// Envoyer la réponse au client
	_, err = conn.Write([]byte(result + "\n"))
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de l'envoi de la réponse au client : %v", err))
		return
	}
}

func SplitArgsPreserveBlocks(input string) []string {
	args := strings.Fields(input)
	var result []string

	i := 0
	for i < len(args) {
		arg := args[i]

		if strings.HasPrefix(arg, "--") {
			// Début d’un nouveau bloc
			key := arg
			i++

			var valueParts []string
			// Lire tous les arguments jusqu’au prochain -- ou fin
			for i < len(args) && !strings.HasPrefix(args[i], "--") {
				valueParts = append(valueParts, args[i])
				i++
			}

			result = append(result, key)
			result = append(result, strings.Join(valueParts, " "))
		} else {
			// Cas des options hors -- (ex: -gpo update)
			result = append(result, arg)
			i++
		}
	}

	return result
}
