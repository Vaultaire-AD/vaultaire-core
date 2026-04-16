package commandupdate

import (
	"fmt"
	"vaultaire/core/database"
)

// Update_Command : pour -pu l'action est dans command_list[2] (ex: read:get:user). Pour -debug on utilise write:update:user.
func Update_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return ("Invalid Request Try get -h for more information")
	case "-pu":
		// update -pu <perm_name> <action_key> nil|all|-a|-r ... — le sender doit avoir write:update:permission
		return update_UserPermission_Command_Parser(command_list, sender_groupsIDs, "write:update:permission", sender_Username)
	case "-u":
		if len(command_list) == 3 {
			db := database.GetDatabase()
			uid, _ := database.Get_User_ID_By_Username(db, command_list[1])
			cur, _ := database.Command_GET_UserInfo(db, command_list[1])
			if err := database.Update_User_Info(db, uid, cur.Username, cur.Firstname, cur.Lastname, command_list[2], ""); err != nil {
				return fmt.Sprintf(">> erreur mise à jour de l'utilisateur : %v", err)
			}
			return "User updated successfully"
		}

	case "-debug":
		return update_Debug_Command_Parser(command_list, sender_groupsIDs, "write:update:user", sender_Username)
	default:
		return ("Invalid Request Try get -h for more information")
	}
	return ("Invalid Request Try get -h for more information")
}
