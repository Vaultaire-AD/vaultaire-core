package commandget

import (
	commandpermission "vaultaire/serveur/command/command_permission"
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	"vaultaire/serveur/database/db_permission"
	"vaultaire/serveur/permission"
	"fmt"
)

// GetPermissionCommandParser traite les commandes "get permission"
func getPermissionCommandParser(commandList []string, senderGroupsIDs []int, action, senderUsername string) string {
	switch len(commandList) {
	case 2:
		return handleGetAllPermissions(commandList[1], senderGroupsIDs, action, senderUsername)

	case 3:
		return handleGetPermissionByName(commandList[1], commandList[2], senderGroupsIDs, action, senderUsername)

	default:
		return commandpermission.InvalidPermissionRequest()
	}
}

// --- Sous-fonctions privées --- //

// handleGetAllPermissions récupère toutes les permissions (-u ou -c)
func handleGetAllPermissions(target string, senderGroupsIDs []int, action, senderUsername string) string {
	// Vérifie les permissions (globale sur tous les domaines)
	if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, []string{"*"}) {
		return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
	}

	switch target {
	case "-u":
		perms, err := db_permission.Command_GET_AllUserPermissions(database.GetDatabase())
		if err != nil {
			return commandpermission.LogAndReturn("Erreur récupération permissions utilisateurs : ", err)
		}
		return display.DisplayAllUserPermissions(perms)

	case "-c":
		perms, err := database.Command_GET_AllClientPermissions(database.GetDatabase())
		if err != nil {
			return commandpermission.LogAndReturn("Erreur récupération permissions clients : ", err)
		}
		return display.DisplayAllClientPermissions(perms)

	default:
		return commandpermission.InvalidPermissionRequest()
	}
}

// handleGetPermissionByName récupère une permission spécifique (-u ou -c)
func handleGetPermissionByName(target, name string, senderGroupsIDs []int, action, senderUsername string) string {
	var (
		domainList []string
		err        error
	)

	// Détermination des domaines en fonction du type de permission
	switch target {
	case "-u":
		domainList, err = permission.GetDomainslistFromUserpermission(name)
	case "-c":
		domainList, err = permission.GetDomainslistFromClientpermission(name)
	default:
		return commandpermission.InvalidPermissionRequest()
	}

	if err != nil {
		return fmt.Sprintf(">> -Erreur récupération domaines de la permission %s : %s", name, err.Error())
	}

	// Vérification d’accès
	if !commandpermission.CheckAccess(senderGroupsIDs, action, senderUsername, domainList) {
		return fmt.Sprintf("Permission refusée pour %s sur %s", senderUsername, action)
	}

	// Récupération et affichage des permissions
	switch target {
	case "-u":
		perm, err := db_permission.Command_GET_UserPermissionByName(database.GetDatabase(), name)
		if err != nil {
			return commandpermission.LogAndReturn(fmt.Sprintf("Erreur récupération permission utilisateur %s : ", name), err)
		}
		return display.DisplayUserPermission(*perm)

	case "-c":
		perm, err := database.Command_GET_ClientPermissionByName(database.GetDatabase(), name)
		if err != nil {
			return commandpermission.LogAndReturn(fmt.Sprintf("Erreur récupération permission client %s : ", name), err)
		}
		return display.DisplayClientPermission(*perm)
	}

	return commandpermission.InvalidPermissionRequest()
}
