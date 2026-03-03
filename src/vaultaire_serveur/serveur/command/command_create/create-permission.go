package commandcreate

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/database/db_permission"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/tools"
)

// create_Permission handles the creation of a user or client permission.
// It expects a command list with the format: ["-p", "-u/-c", "permission_name", "description"].
// If the command is valid, it creates the permission and returns a success message.
// If the command is invalid or an error occurs, it logs the error and returns an error message.
func create_Permission(command_list []string) string {
	if len(command_list) < 4 {
		return ("Erreur : -p -u <nom_de_la_permissions> <description_attaché> / -p -c <nom_de_la_permissions> <yes/not> ")
	} else {
		switch expression := command_list[1]; expression {
		case "-u":
			_, err := db_permission.CreateUserPermissionDefault(database.GetDatabase(), command_list[2], command_list[3])
			if err != nil {
				logs.Write_Log("WARNING", "error during the creation of the user_permission "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "new user_permission create with succes with Name: "+command_list[2]+" and permission admin : ")
			return ("new user_permission create with succes with Name: " + command_list[2] + " and permission admin : ")
		case "-c":
			isValid := tools.String_tobool_yesnot(command_list[3])
			_, err := db_permission.CreateClientPermission(database.GetDatabase(), command_list[2], isValid)
			if err != nil {
				logs.Write_Log("WARNING", "error during the creation of the client_permission "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "new client_permission create with succes with Name: "+command_list[2]+" and permission admin : "+command_list[3])
			return ("new client_permission create with succes with Name: " + command_list[2] + " and permission admin : " + command_list[3])
		default:
			return ("Erreur : -p -u/c <nom_de_la_permissions> <yes/not> pour crée un nouvelle permisions admin ou non seulement pour les permissions client")

		}

	}
}
