package commandadd

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	dbuser "DUCKY/serveur/database/db-user"
	"DUCKY/serveur/logs"
	"strings"
)

// add_User_Command_Parser handles the addition of a user to a group.
// It expects a command list with the format: ["add", "username", "-g", "group_name"].
// If the command is valid, it adds the user to the group and returns the updated user information.
// If the command is invalid or an error occurs, it logs the error and returns an error message.
func add_User_Command_Parser(command_list []string) string {
	if len(command_list) < 4 {
		return "\nMiss Argument: get -h for more information or consult man on the wiki"
	}

	switch command_list[2] {
	case "-g":
		// Ajouter l'utilisateur à un groupe
		err := database.Command_ADD_UserToGroup(database.GetDatabase(), command_list[1], command_list[3])
		if err != nil {
			logs.Write_Log("WARNING", "Error adding group "+command_list[3]+" to user "+command_list[1]+": "+err.Error())
			return ">> -" + err.Error()
		}
		user, err := database.Command_GET_UserInfo(database.GetDatabase(), command_list[1])
		if err != nil {
			logs.Write_Log("WARNING", "Error fetching user info for "+command_list[1]+": "+err.Error())
			return ">> -" + err.Error()
		}
		logs.Write_Log("INFO", "Added group "+command_list[3]+" to user "+command_list[1])
		return display.DisplayUsersInfoByName(user)

	case "-k":
		// Ajouter une clé publique à l'utilisateur
		if len(command_list) < 5 {
			return ">> -Missing argument: label or key is empty. Usage: vlt add user <username> -k <label> <key>"
		}

		userId, err := database.Get_User_ID_By_Username(database.GetDatabase(), strings.TrimSpace(command_list[1]))
		if err != nil {
			logs.Write_Log("WARNING", "Error fetching user ID for "+command_list[1]+": "+err.Error())
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
			logs.Write_Log("WARNING", "Error adding public key to user "+command_list[1]+": "+err.Error())
			return ">> -" + err.Error()
		}

		logs.Write_Log("INFO", "Added public key to user "+command_list[1])
		pubKeys, err := dbuser.GetUserKeys(userId)
		if err != nil || len(pubKeys) == 0 {
			logs.Write_Log("WARNING", "No public keys found for user "+command_list[1]+": "+err.Error())
			return ">> -No public key found for this user"
		}

		return display.DisplayUserPublicKeys(command_list[1], pubKeys)

	default:
		return "\nMiss Argument: get -h for more information or consult man on the wiki"
	}
}
