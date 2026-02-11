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

	// Routage RBAC : chaque commande détermine elle-même la clé d'action (catégorie:action:objet)
	commandTable := map[string]func([]string, []int, string) string{
		"add":    commandadd.Add_Command,
		"remove": commandremove.Remove_Command,
		"update": commandupdate.Update_Command,
		"delete": commanddelete.Delete_Command,
		"dns":    commanddns.DNS_Command,
		"status": commandstatus.Status_Command,
		"create": commandcreate.Create_Command,
		"get":    commandget.Get_Command,
		"eyes":   commandeyes.Eyes_Command,
	}

	if cmd == "clear" {
		return handleClear(sender)
	}
	if cmd == "help" {
		return `Commandes disponibles :
  create [OPTIONS] : crée une nouvelle entrée.
  status [OPTIONS] : Vérifie l'état du serveur.
  clear            : Nettoie les sessions.
  help             : Affiche cette aide.`
	}

	entry, ok := commandTable[cmd]
	if !ok {
		return fmt.Sprintf("Commande inconnue : %s. Tapez 'help' pour plus d'informations.", cmd)
	}

	groupIDs, err := permission.GetGroupIDsForUser(sender)
	if err != nil {
		return "Erreur de permission : " + err.Error()
	}

	return entry(argv, groupIDs, sender)
}

func handleClear(sender string) string {
	groupIDs, err := permission.GetGroupIDsForUser(sender)
	if err != nil {
		return "Erreur de permission : " + err.Error()
	}
	ok, msg := permission.CheckPermissionsMultipleDomains(groupIDs, "write:update:user", []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=write:update:user reason=%s", sender, msg))
		return "Permission refusée : " + msg
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=write:update:user (clear)", sender))
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
