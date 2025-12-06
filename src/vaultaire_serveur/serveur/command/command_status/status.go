package commandstatus

func Status_Command(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return (`
status -u (Lister les utilisateurs connectés)

Commande :
  status -u

Arguments :
  - Filtrer par nom d'utilisateur :
      status -u "username"

  - Lister tous les utilisateurs d'un groupe :
      status -u -g "group_name"

  - Lister tous les utilisateurs d'une permission :
      status -u -p "permission_name"

--------------------------------------------------

status -c (Lister les clients connectés)

Commande :
  status -c

Arguments :
  - Lister les clients par type :
      status -c <type_client>

  - Lister les clients par permission :
      status -c -p "permission_name"

  - Lister les clients par groupe :
      status -c -g "group_name"
`)
	case "-u":
		return status_User_Command_Parser(command_list, sender_groupsIDs, action, sender_Username)
	case "-c":
		return status_Client_Command_Parser(command_list, sender_groupsIDs, action, sender_Username)
	default:
		return ("Erreur de formatage status -h for help")
	}
}
