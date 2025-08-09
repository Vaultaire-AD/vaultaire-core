package commandadd

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

// add_GPO_Command_Parser handles the addition of a GPO to a group.
// It expects a command list with the format: ["-gpo", "group_name", "-g", "gpo_name"].
// If the command is valid, it adds the GPO to the group and returns the updated group information.
// If the command is invalid or an error occurs, it logs the error and returns an empty string.
func add_GPO_Command_Parser(command_list []string) string {
	if len(command_list) == 4 {
		switch command_list[0] {
		case "-gpo":
			err := database.Command_ADD_GPOToGroup(database.GetDatabase(), command_list[1], command_list[3])
			if err != nil {
				logs.Write_Log("WARNING", "Error for add gpo "+command_list[3]+" to group "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "Add to group : "+command_list[1]+" gpo : "+command_list[3])
			return post_displayGroupInfo(command_list[3])
		default:
			return ("Invalid Request Try add -gpo gpo_name -g group_name for more information : " + command_list[0])
		}
	}
	return ("Invalid Request Try get -h for more information")
}
