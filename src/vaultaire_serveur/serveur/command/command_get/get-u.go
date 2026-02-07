package commandget

import (
	commandpermission "vaultaire/serveur/command/command_permission"
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	dbuser "vaultaire/serveur/database/db-user"
	"vaultaire/serveur/permission"
	"fmt"
	"strings"
)

// GetUserCommandParser traite les commandes "get user"
func getUserCommandParser(commandList []string, senderGroupsIDs []int, action, senderUsername string) string {
	switch len(commandList) {
	case 1:
		return handleGetAllUsers(senderGroupsIDs, action, senderUsername)

	case 2:
		return handleGetUserInfo(commandList[1], senderGroupsIDs, action, senderUsername)

	case 3:
		return handleGetUserSubcommand(commandList, senderGroupsIDs, action, senderUsername)

	default:
		return commandpermission.InvalidPermissionRequest()
	}
}

// --- Sous-fonctions privées --- //

// handleGetAllUsers retourne la liste de tous les utilisateurs
func handleGetAllUsers(senderGroupsIDs []int, action, senderUsername string) string {
	if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, []string{"*"}) {
		return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
	}

	users, err := database.Command_GET_AllUsers(database.GetDatabase())
	if err != nil {
		return commandpermission.LogAndReturn("Erreur lors de la récupération des utilisateurs : ", err)
	}
	return display.DisplayAllUsers(users)
}

// handleGetUserInfo retourne les infos détaillées d’un utilisateur
func handleGetUserInfo(username string, senderGroupsIDs []int, action, senderUsername string) string {
	domainList, err := permission.GetDomainListFromUsername(senderUsername)
	if err != nil {
		return fmt.Sprintf(">> -Erreur récupération domaines pour l'utilisateur %s : %s", username, err.Error())
	}

	if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, domainList) {
		return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
	}

	userInfo, err := database.Command_GET_UserInfo(database.GetDatabase(), username)
	if err != nil {
		return commandpermission.LogAndReturn("Erreur récupération utilisateur "+username+" : ", err)
	}
	return display.DisplayUsersInfoByName(userInfo)
}

// handleGetUserSubcommand traite les sous-commandes (-g et -k)
func handleGetUserSubcommand(commandList []string, senderGroupsIDs []int, action, senderUsername string) string {
	subcmd, arg := commandList[1], commandList[2]

	switch subcmd {
	case "-g": // Récupère les utilisateurs par groupe
		users, err := database.Command_GET_UsersByGroup(database.GetDatabase(), arg)
		if err != nil {
			return commandpermission.LogAndReturn("Erreur récupération utilisateurs du groupe "+arg+" : ", err)
		}
		return display.DisplayUsersByGroup(arg, users)
	}

	// Exemple : get user bob -k
	if arg == "-k" {
		username := strings.TrimSpace(commandList[1])
		userID, err := database.Get_User_ID_By_Username(database.GetDatabase(), username)
		if err != nil {
			return commandpermission.LogAndReturn("Erreur récupération ID utilisateur "+username+" : ", err)
		}

		pubKeys, err := dbuser.GetUserKeys(userID)
		if err != nil || len(pubKeys) == 0 {
			return ">> -No public key found for this user"
		}
		return display.DisplayUserPublicKeys(username, pubKeys)
	}

	return commandpermission.InvalidPermissionRequest()
}
