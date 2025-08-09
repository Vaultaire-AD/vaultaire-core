package commandcreate

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/logs"
	newclient "DUCKY/serveur/new_client"
	autoaddclientgo "DUCKY/serveur/new_client/AUTO_ADD_client.go"
	"DUCKY/serveur/tools"
)

// Management pour les commandes create
func Create_Command(command_list []string) string {
	switch command_list[0] {
	case "-h", "help", "--help":
		return (`"La commande create vous permets de crée des nouveau utilisateur ou des nouveaux clients_software de nouvelles permissions et de nouveau groupes")
		"-u path to yaml user pour crée un nouvelle utilisateur"
		"-c <type_client> <yes/not(serveur or not)> pour crée un nouveau client software"
		"-g <nom_du_goupe> <nom_de_la_perm> pour crée un nouveau groupe"
		"-p <nom_de_la_permissions> <yes/not> pour crée un nouvelle permisions admin ou non"`)
	case "-u":
		return create_User(command_list)
	case "-c":
		return create_ClientSoftware(command_list)
	case "-g":
		return create_Group(command_list)
	case "-p":
		return create_Permission(command_list)
	case "-gpo":
		return create_GPO(command_list)
	default:
		return ("Invalid Request Try get -h for more information")
	}
}

// create_User handles the creation of a user from a YAML file.
func create_Group(command_list []string) string {
	// ajouter des user dans la db via yml
	if len(command_list) < 2 {
		return ("Erreur : -g <nom_du_goupe> <domain>")
	} else {
		_, err := database.CreateGroup(database.GetDatabase(), command_list[1], command_list[2])
		if err != nil {
			logs.Write_Log("WARNING", "error during the creation of the group "+command_list[1]+" : "+err.Error())
			return (">> -" + err.Error())
		}
		logs.Write_Log("INFO", "new Group create with succes with Name : "+command_list[1])
		groupDetails, err := database.Command_GET_GroupInfo(database.GetDatabase(), command_list[1])
		if err != nil {
			return (">> -" + err.Error())
		}
		logs.Write_Log("INFO", "Group details : "+groupDetails.Name)
		return display.DisplayGroupInfo(groupDetails)
	}
}

func create_ClientSoftware(command_list []string) string {
	if len(command_list) < 3 {
		return ("Erreur : create -c \"client_software type\" <yes/not> serveur ou non")
	} else {
		isValid := tools.String_tobool_yesnot(command_list[2])
		computeurID, err := newclient.GenerateClientSoftware(command_list[1], isValid)
		if err != nil {
			logs.Write_Log("WARNING", "error during the creation of the client software "+command_list[1]+" : "+err.Error())
			return err.Error()
		}
		logs.Write_Log("INFO", "new client create with succes with this ID : "+computeurID)
		if command_list[3] == "-join" {
			return autoaddclientgo.Manage_Auto_ADD_client(command_list[5], command_list[4], computeurID)
		}
		return ("new client create with succes with this ID : " + computeurID)
	}
}
