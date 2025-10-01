package commandget

func Get_Command(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return (`
get Permet d'afficher des informations sur les utilisateurs, groupes, permissions ou clients.
get -u (Informations sur un utilisateur)

get -u "username"

Lister tous les utilisateurs d'une permission :

get -u -p "permission_name"

Lister tous les utilisateurs d'un groupe :

get -u -g "group_name"

get -p (Lister les permissions et leurs groupes associés)

get -p -g

get -p -u

get -g (Lister les groupes et leurs permissions associées)

get -g

Lister tous les clients d'un groupe :

get -g -c "group_name"

Lister tous les utilisateurs d'un groupe :

get -g -u "group_name"`)
	case "-u":
		return get_User_Command_Parser(command_list, sender_groupsIDs, action, sender_Username)
	case "-p":
		return get_Permission_Command_Parser(command_list)
	case "-g":
		return get_Group_Command_Parser(command_list)
	case "-c":
		return get_Client_Command_Parser(command_list)
	case "-gpo":
		return get_GPO_Command_Parser(command_list)
	default:
		return ("Invalid Request Try get -h for more information")
	}
}
