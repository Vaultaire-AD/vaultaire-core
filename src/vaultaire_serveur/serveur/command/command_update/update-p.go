package commandupdate

import (
	"DUCKY/serveur/command/display"
	"DUCKY/serveur/database"
	"DUCKY/serveur/database/db_permission"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
)

// update_UserPermission_Command_Parser interprète et exécute une commande de mise à jour de permission utilisateur
func update_UserPermission_Command_Parser(command_list []string) string {
	// Vérification du nombre minimal d’arguments
	if len(command_list) < 4 {
		return "Invalid Request. Try update -h for more information"
	}

	// Parsing des arguments
	permissionName := command_list[1]
	action := command_list[2]
	arg := command_list[3]
	childOrAll := "0"

	var domain string

	// Si l’action attend un domaine
	if arg == "-a" || arg == "-r" {
		if len(command_list) != 6 {
			return "Invalid Request. Try update -h for more information"
		}
		childOrAll = command_list[4]
		domain = command_list[5]
	}

	// Récupération de l’ID de la permission
	permissionID, err := db_permission.Command_GET_UserPermissionID(database.GetDatabase(), permissionName)
	if err != nil {
		return fmt.Sprintf(">> erreur récupération ID de la permission : %v", err)
	}

	logs.Write_Log("DEBUG", fmt.Sprintf(
		"Update -pu: name=%s action=%s arg=%s child_or_all=%s domain=%s",
		permissionName, action, arg, childOrAll, domain,
	))

	// Récupération du contenu actuel
	currentContent, err := db_permission.Command_GET_UserPermissionAction(database.GetDatabase(), permissionID, action)
	if err != nil {
		logs.Write_Log("ERROR", "Update -pu Get user permission action content : "+err.Error())
	}
	parsedContent := permission.ParsePermissionAction(currentContent)
	logs.Write_Log("DEBUG", permission.FormatPermissionAction(parsedContent))

	// Gestion des types d’arguments
	switch arg {
	case "nil", "all":
		// Mise à jour simple
		parsedContent.Type = arg
		if err := db_permission.Command_SET_UserPermissionAction(database.GetDatabase(), permissionID, action, arg); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Update -pu Set user permission action '%s' : %v", arg, err))
		}

	case "-a":
		// Ajouter domaine

		permission.UpdatePermissionAction(&parsedContent, domain, childOrAll, true)
		newValue := permission.ConvertPermissionActionToString(parsedContent)
		if err := db_permission.Command_SET_UserPermissionAction(database.GetDatabase(), permissionID, action, newValue); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Impossible d'ajouter le domaine %s : %v", domain, err))
		} else {
			logs.Write_Log("DEBUG", fmt.Sprintf("Domaine ajouté %s (option %s)", domain, childOrAll))
		}

	case "-r":
		// Retirer domaine
		permission.UpdatePermissionAction(&parsedContent, domain, childOrAll, false)

		// Si plus aucun domaine, passer en nil
		if len(parsedContent.WithPropagation) == 0 && len(parsedContent.WithoutPropagation) == 0 {
			parsedContent.Type = "nil"
			newValue := "nil"
			if err := db_permission.Command_SET_UserPermissionAction(database.GetDatabase(), permissionID, action, newValue); err != nil {
				logs.Write_Log("ERROR", fmt.Sprintf("Impossible de passer l'action à nil : %v", err))
			} else {
				logs.Write_Log("DEBUG", fmt.Sprintf("Aucun domaine restant, action %s passe en nil", action))
			}
		} else {
			// Sinon, sauvegarder la nouvelle valeur
			newValue := permission.ConvertPermissionActionToString(parsedContent)
			if err := db_permission.Command_SET_UserPermissionAction(database.GetDatabase(), permissionID, action, newValue); err != nil {
				logs.Write_Log("ERROR", fmt.Sprintf("Impossible de retirer le domaine %s : %v", domain, err))
			} else {
				logs.Write_Log("DEBUG", fmt.Sprintf("Domaine retiré %s (option %s)", domain, childOrAll))
			}
		}

	default:
		return fmt.Sprintf("Invalid argument '%s'. Try update -h for more information", arg)
	}
	// Récupération finale de la permission mise à jour
	perm, err := db_permission.Command_GET_UserPermissionByName(database.GetDatabase(), permissionName)
	if err != nil {
		return ">> -" + err.Error()
	}
	return display.DisplayUserPermission(*perm)
}
