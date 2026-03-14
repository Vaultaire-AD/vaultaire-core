package commandeyes

func Eyes_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return ("vaultaire eyes Permet de voir les elements classé dans un equivalent de l'Active Directory!")
	case "-g":
		return eyes_by_domain(command_list, sender_groupsIDs, "write:eyes", sender_Username)
	default:
		return ("Invalid Request Try get -h for more information")
	}
}
