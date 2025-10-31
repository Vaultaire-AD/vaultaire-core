package commandremove

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	dbuser "DUCKY/serveur/database/db-user"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
	"strconv"
)

// remove_User_Command_Parser traite la commande "remove user"
func remove_User_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	if len(command_list) != 4 {
		return "\nMiss Argument remove -h for more information or consult man on the wiki"
	}

	username := command_list[1]
	option := command_list[2]
	target := command_list[3]

	// 🔹 Étape 1 : Récupération des groupes de l'utilisateur cible
	domains, err := permission.GetDomainListFromUsername(username)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération groupes de %s : %v", username, err))
		return fmt.Sprintf("Erreur récupération groupes de %s : %v", username, err)
	}

	// 🔹 Étape 3 : Vérification des permissions du sender sur ces domaines
	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente de retirer %s (domaines : %v) — %s",
			sender_Username, username, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}

	db := database.GetDatabase()

	switch option {
	case "-g":
		// 🔹 Retirer l'utilisateur d'un groupe
		if err := database.Command_Remove_UserFromGroup(db, username, target); err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur suppression de %s du groupe %s : %v", username, target, err))
			return ">> -" + err.Error()
		}

		userInfo, err := database.Command_GET_UserInfo(db, username)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération infos utilisateur %s : %v", username, err))
			return ">> -" + err.Error()
		}

		logs.Write_Log("INFO", fmt.Sprintf("Utilisateur %s retiré du groupe %s", username, target))
		return display.DisplayUsersInfoByName(userInfo)

	case "-k":
		// 🔹 Retirer une clé publique
		keyID, err := strconv.Atoi(target)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur conversion KeyID %s : %v", target, err))
			return ">> -" + err.Error()
		}

		if err := dbuser.DeleteUserKeys([]int{keyID}); err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur suppression clé ID %d de %s : %v", keyID, username, err))
			return ">> -" + err.Error()
		}

		userID, err := database.Get_User_ID_By_Username(db, username)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération ID utilisateur %s : %v", username, err))
			return ">> -" + err.Error()
		}

		pubKeys, err := dbuser.GetUserKeys(userID)
		if err != nil || len(pubKeys) == 0 {
			logs.Write_Log("WARNING", fmt.Sprintf("Pas de clé publique trouvée pour %s", username))
			return ">> -No public key found for this user"
		}

		logs.Write_Log("INFO", fmt.Sprintf("Clé publique ID %d retirée de %s", keyID, username))
		return display.DisplayUserPublicKeys(username, pubKeys)

	default:
		return "\nMiss Argument remove -h for more information or consult man on the wiki"
	}
}
