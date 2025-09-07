package commandremove

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	dbuser "DUCKY/serveur/database/db-user"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"strconv"
)

func remove_User_Command_Parser(command_list []string) string {
	if len(command_list) == 4 {
		switch command_list[2] {
		case "-g":
			err := database.Command_Remove_UserFromGroup(database.GetDatabase(), command_list[1], command_list[3])
			if err != nil {
				logs.Write_Log("WARNING", "error during the removal of the user "+command_list[1]+" From "+command_list[3]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			user_Info, err := database.Command_GET_UserInfo(database.GetDatabase(), command_list[1])
			if err != nil {
				logs.Write_Log("WARNING", "error during the get of the user "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			logs.Write_Log("INFO", "User "+command_list[1]+" removed from group "+command_list[3])
			return display.DisplayUsersInfoByName(user_Info)
		case "-k":
			KeyID, err := strconv.Atoi(command_list[3])
			if err != nil {
				logs.Write_Log("WARNING", "vlt remove -u <username> -k <KeyId> error during the conversion of the keyID "+command_list[3]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			err = dbuser.DeleteUserKeys([]int{KeyID})
			if err != nil {
				logs.Write_Log("WARNING", "error during the removal of the public key ID "+command_list[3]+" to the user "+command_list[1]+" : "+err.Error())
				return (">> -" + err.Error())
			}
			userId, err := database.Get_User_ID_By_Username(database.GetDatabase(), command_list[1])
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
			logs.Write_Log("INFO", "Public key ID "+command_list[3]+" removed from user "+command_list[1])
			return display.DisplayUserPublicKeys(command_list[1], pubKeys)
		default:
			return ("\nMiss Argument status -h for more information or consult man on the wiki")
		}
	}
	return ("\nMiss Argument status -h for more information or consult man on the wiki")
}
