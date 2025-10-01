package commandget

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	dbuser "DUCKY/serveur/database/db-user"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
)

func get_User_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) == 1 {
		isactionlegitimate, response := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, []string{"*"})
		if !isactionlegitimate {
			logs.Write_Log("WARNING", fmt.Sprintf("Permission refusée pour l'utilisateur %s sur l'action %s : %s", sender_Username, action, response))
			return fmt.Sprintf("Permission refusée : %s", response)
		}
		users, err := database.Command_GET_AllUsers(database.GetDatabase())
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of all users : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayAllUsers(users)

	}
	if len(command_list) == 2 {
		domainList, err := permission.GetDomainListFromUsername(sender_Username)
		if err != nil {
			return ">> -Erreur lors de la récupération des domaines de l'utilisateur."
		}
		isactionlegitimate, response := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domainList)
		if !isactionlegitimate {
			logs.Write_Log("WARNING", fmt.Sprintf("Permission refusée pour l'utilisateur %s sur l'action %s : %s", sender_Username, action, response))
			return fmt.Sprintf("Permission refusée : %s", response)
		}
		user_Info, err := database.Command_GET_UserInfo(database.GetDatabase(), command_list[1])
		if err != nil {
			logs.Write_Log("WARNING", "error during the get of the user "+command_list[1]+" : "+err.Error())
			return (">> -" + err.Error())
		}
		return display.DisplayUsersInfoByName(user_Info)
	} else if len(command_list) == 3 {
		switch command_list[1] {
		case "-g":
			user_Info, err := database.Command_GET_UsersByGroup(database.GetDatabase(), command_list[2])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the user "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			return display.DisplayUsersByGroup(command_list[2], user_Info)
		}
		if command_list[2] == "-k" {
			userId, err := database.Get_User_ID_By_Username(database.GetDatabase(), strings.TrimSpace(command_list[1]))
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the userid "+command_list[2]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			pubKeys := []storage.PublicKey{}
			pubKeys, err = dbuser.GetUserKeys(userId)
			if err != nil || len(pubKeys) == 0 {
				logs.Write_Log("WARNING", "error during the get of the public key of the user "+command_list[2]+" : "+err.Error())
				return (">> -No public key found for this user")
			}
			return display.DisplayUserPublicKeys(command_list[2], pubKeys)
		}
	}
	return ("\nMiss Argument get -h for more information or consult man on the wiki")
}
