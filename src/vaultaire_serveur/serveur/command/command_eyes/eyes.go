package commandeyes

// Management pour les commandes eyes
func Eyes_Command(command_list []string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return ("vaultaire eyes Permet de voir les elements classé dans un equivalent de l'Active Directory!")
	case "-g":
		return eyes_by_domain(command_list)
	default:
		return ("Invalid Request Try get -h for more information")
	}
}
