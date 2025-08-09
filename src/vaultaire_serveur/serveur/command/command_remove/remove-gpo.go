package commandremove

import (
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
)

func remove_GPO_Command_Parser(command_list []string) string {
	if len(command_list) == 4 {
		switch command_list[0] {
		case "-gpo":
			err := database.Command_REMOVE_GPOFromGroup(database.GetDatabase(), command_list[1], command_list[3])
			if err != nil {
				logs.Write_Log("WARNING", "error during the removal of the GPO "+command_list[1]+" From "+command_list[3]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "GPO "+command_list[1]+" removed from group "+command_list[3])
			return post_displayGroupInfo(command_list[3])
		default:
			return ("Invalid Request Try remove -gpo gpo_name -g group_name or get -h for more information : " + command_list[0])
		}
	}
	return ("Invalid Request Try get -h for more information")
}
