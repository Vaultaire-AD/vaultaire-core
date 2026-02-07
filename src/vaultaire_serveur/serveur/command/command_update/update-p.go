package commandupdate

import (
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	"vaultaire/serveur/database/db_permission"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"fmt"
)

// update_UserPermission_Command_Parser interprète et exécute une commande de mise à jour de permission utilisateur
func update_UserPermission_Command_Parser(command_list []string, sender_groupsIDs []int, Useraction, sender_Username string) string {
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

	db := database.GetDatabase()

	// 🔹 Étape 0 : Vérification des permissions du sender sur cette permission
	domains, err := permission.GetDomainslistFromUserpermission(permissionName)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines de la permission %s : %v", permissionName, err))
		return fmt.Sprintf("Erreur récupération domaines de la permission %s : %v", permissionName, err)
	}

	ok, reason := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, Useraction, domains)
	if !ok {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"%s tente de modifier la permission %s (domaines : %v) — %s",
			sender_Username, permissionName, domains, reason,
		))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}

	// 🔹 Étape 1 : Récupération de l’ID de la permission
	permissionID, err := db_permission.Command_GET_UserPermissionID(db, permissionName)
	if err != nil {
		return fmt.Sprintf(">> erreur récupération ID de la permission : %v", err)
	}

	logs.Write_Log("DEBUG", fmt.Sprintf(
		"Update -pu: name=%s action=%s arg=%s child_or_all=%s domain=%s",
		permissionName, action, arg, childOrAll, domain,
	))

	// 🔹 Étape 2 : Récupération du contenu actuel
	currentContent, err := db_permission.Command_GET_UserPermissionAction(db, permissionID, action)
	if err != nil {
		logs.Write_Log("ERROR", "Update -pu Get user permission action content : "+err.Error())
	}
	parsedContent := permission.ParsePermissionAction(currentContent)
	logs.Write_Log("DEBUG", permission.FormatPermissionAction(parsedContent))

	// 🔹 Étape 3 : Gestion des types d’arguments
	switch arg {
	case "nil", "all":
		parsedContent.Type = arg
		if err := db_permission.Command_SET_UserPermissionAction(db, permissionID, action, arg); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Update -pu Set user permission action '%s' : %v", arg, err))
		}

	case "-a":
		// Ajouter domaine
		permission.UpdatePermissionAction(&parsedContent, domain, childOrAll, true)
		newValue := permission.ConvertPermissionActionToString(parsedContent)
		if err := db_permission.Command_SET_UserPermissionAction(db, permissionID, action, newValue); err != nil {
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
			if err := db_permission.Command_SET_UserPermissionAction(db, permissionID, action, newValue); err != nil {
				logs.Write_Log("ERROR", fmt.Sprintf("Impossible de passer l'action à nil : %v", err))
			} else {
				logs.Write_Log("DEBUG", fmt.Sprintf("Aucun domaine restant, action %s passe en nil", action))
			}
		} else {
			// Sinon, sauvegarder la nouvelle valeur
			newValue := permission.ConvertPermissionActionToString(parsedContent)
			if err := db_permission.Command_SET_UserPermissionAction(db, permissionID, action, newValue); err != nil {
				logs.Write_Log("ERROR", fmt.Sprintf("Impossible de retirer le domaine %s : %v", domain, err))
			} else {
				logs.Write_Log("DEBUG", fmt.Sprintf("Domaine retiré %s (option %s)", domain, childOrAll))
			}
		}

	default:
		return fmt.Sprintf("Invalid argument '%s'. Try update -h for more information", arg)
	}

	// 🔹 Étape 4 : Récupération finale de la permission mise à jour
	perm, err := db_permission.Command_GET_UserPermissionByName(db, permissionName)
	if err != nil {
		return ">> -" + err.Error()
	}
	return display.DisplayUserPermission(*perm)
}
