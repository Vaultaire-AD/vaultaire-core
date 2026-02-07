package command

import (
	commandadd "vaultaire/serveur/command/command_add"
	commandcreate "vaultaire/serveur/command/command_create"
	commanddelete "vaultaire/serveur/command/command_delete"
	commanddns "vaultaire/serveur/command/command_dns"
	commandeyes "vaultaire/serveur/command/command_eyes"
	commandget "vaultaire/serveur/command/command_get"
	commandremove "vaultaire/serveur/command/command_remove"
	commandstatus "vaultaire/serveur/command/command_status"
	commandupdate "vaultaire/serveur/command/command_update"
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
	"net"
	"strings"
)

// Exécute une commande et retourne le résultat
func ExecuteCommand(input, sender string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return "Erreur : commande vide."
	}

	args := SplitArgsPreserveBlocks(input)
	if len(args) == 0 {
		return "Erreur : commande vide."
	}
	if len(args) == 1 {
		args = append(args, "-h")
	}

	cmd, argv := args[0], args[1:]

	// Table de routage rapide
	commandTable := map[string]struct {
		perm   string
		action func([]string, []int, string, string) string
	}{

		"add":    {"api_write_permission", commandadd.Add_Command},
		"remove": {"api_write_permission", commandremove.Remove_Command},
		"update": {"api_write_permission", commandupdate.Update_Command},
		"delete": {"api_write_permission", commanddelete.Delete_Command},
		"dns":    {"api_write_permission", commanddns.DNS_Command},
		"status": {"api_read_permission", commandstatus.Status_Command},
		"create": {"api_write_permission", commandcreate.Create_Command},
		"get":    {"api_read_permission", commandget.Get_Command},
		"eyes":   {"api_write_permission", commandeyes.Eyes_Command},
	}

	// Commande spéciale clear (plus rapide ici)
	if cmd == "clear" {
		return handleClear(sender)
	}

	// Commande help
	if cmd == "help" {
		return `Commandes disponibles :
  create [OPTIONS] : crée une nouvelle entrée.
  status [OPTIONS] : Vérifie l'état du serveur.
  clear            : Nettoie les sessions.
  help             : Affiche cette aide.`
	}

	// Recherche dans la table
	entry, ok := commandTable[cmd]
	if !ok {
		return fmt.Sprintf("Commande inconnue : %s. Tapez 'help' pour plus d'informations.", cmd)
	}

	// Si aucune permission requise (ex: status)
	if entry.perm == "" {
		return entry.action(argv, nil, "", sender)
	}

	// Vérification des permissions
	groupIDs, action, err := permission.PrePermissionCheck(sender, entry.perm)
	if err != nil {
		return "Erreur de permission : " + err.Error()
	}

	return entry.action(argv, groupIDs, action, sender)
}

func handleClear(sender string) string {
	groupIDs, action, err := permission.PrePermissionCheck(sender, "api_write_permission")
	if err != nil {
		return "Erreur de permission : " + err.Error()
	}
	ok, msg := permission.CheckPermissionsMultipleDomains(groupIDs, action, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refusée pour %s : %s", sender, msg))
		return "Permission refusée : " + msg
	}
	if err := database.CleanUpExpiredSessions(database.DB); err != nil {
		logs.Write_Log("ERROR", "Erreur nettoyage sessions : "+err.Error())
		return "Erreur lors du nettoyage des sessions expirées."
	}
	return "Sessions expirées nettoyées."
}

// Version optimisée : aucune copie de slice inutile
func SplitArgsPreserveBlocks(input string) []string {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil
	}

	res := make([]string, 0, len(parts))
	for i := 0; i < len(parts); {
		arg := parts[i]
		if strings.HasPrefix(arg, "--") {
			key := arg
			i++
			start := i
			for i < len(parts) && !strings.HasPrefix(parts[i], "--") {
				i++
			}
			res = append(res, key)
			if i > start {
				res = append(res, strings.Join(parts[start:i], " "))
			}
		} else {
			res = append(res, arg)
			i++
		}
	}
	return res
}

func HandleClientCLI(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur fermeture connexion : %v", err))
		}
	}()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Erreur lecture :", err)
		return
	}

	command := strings.TrimSpace(string(buf[:n]))
	result := ExecuteCommand(command, "vaultaire")

	if _, err := conn.Write([]byte(result + "\n")); err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur envoi client : %v", err))
	}
}
