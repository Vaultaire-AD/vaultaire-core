package commandadd

import (
	"fmt"
	"strings"
	"vaultaire/core/command/display"
	"vaultaire/core/database"
	dbuser "vaultaire/core/database/db-user"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

func add_User_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) < 4 {
		return "\nMissing arguments: use get -h for more information or consult the wiki"
	}

	username := command_list[1]
	argType := command_list[2]

	// 🔹 Étape 1 : Récupération des groupes/domaines de l'utilisateur cible (si existant)
	domains, err := permission.GetDomainListFromUsername(username)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération groupes pour %s : %v", username, err))
		return fmt.Sprintf("Erreur récupération groupes pour %s : %v", username, err)
	}

	// 🔹 Étape 2 : Vérification des permissions
	ok, reason := permission.CheckPermissionsAllDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s target=%s reason=%s", sender_Username, action, username, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente d'ajouter %s (domaines : %v) — %s", sender_Username, username, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (add user)", sender_Username, action))

	switch argType {
	case "-g":
		groupName := command_list[3]
		err := database.Command_ADD_UserToGroup(database.GetDatabase(), username, groupName)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur ajout %s au groupe %s : %v", username, groupName, err))
			return ">> -" + err.Error()
		}
		userInfo, err := database.Command_GET_UserInfo(database.GetDatabase(), username)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération info utilisateur %s : %v", username, err))
			return ">> -" + err.Error()
		}
		logs.Write_Log("INFO", fmt.Sprintf("Utilisateur %s ajouté au groupe %s", username, groupName))
		return display.DisplayUsersInfoByName(userInfo)

	case "-k":
		if len(command_list) < 5 {
			return ">> -Missing argument: label or key is empty. Usage: vlt add user <username> -k <label> <key>"
		}
		userId, err := database.Get_User_ID_By_Username(database.GetDatabase(), strings.TrimSpace(username))
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération ID utilisateur %s : %v", username, err))
			return ">> -" + err.Error()
		}
		pubkey := strings.Join(command_list[4:], " ")
		if pubkey == "" || command_list[3] == "" {
			return ">> -Missing argument: label or key is empty. Usage: vlt add user <username> -k <label> <key>"
		}
		if !strings.HasPrefix(pubkey, "ssh-rsa") && !strings.HasPrefix(pubkey, "ssh-ed25519") {
			return ">> -The key must start with 'ssh-rsa' or 'ssh-ed25519'"
		}
		err = dbuser.AddUserKey(userId, pubkey, command_list[3])
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur ajout clé publique à %s : %v", username, err))
			return ">> -" + err.Error()
		}
		logs.Write_Log("INFO", fmt.Sprintf("Clé publique ajoutée à %s", username))
		pubKeys, err := dbuser.GetUserKeys(userId)
		if err != nil || len(pubKeys) == 0 {
			logs.Write_Log("WARNING", fmt.Sprintf("Aucune clé publique trouvée pour %s : %v", username, err))
			return ">> -No public key found for this user"
		}
		return display.DisplayUserPublicKeys(username, pubKeys)

	default:
		return "\nMissing arguments: use get -h for more information or consult the wiki"
	}
}
