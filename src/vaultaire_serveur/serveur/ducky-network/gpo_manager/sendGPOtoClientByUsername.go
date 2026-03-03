package gpomanager

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/tools"
	"strings"
)

func Get_GPO_forClient(username string, clientsoftware string) (string, error) {
	db := database.GetDatabase()
	clientOS, err := database.GetClientOS(db, clientsoftware)
	if err != nil {
		return "", err
	}
	clientOS = tools.DetectOSName(clientOS)
	groupName, err := database.GetUserGroupNameWhenLogin(db, username, clientsoftware)
	if err != nil {
		return "", err
	}
	commands, err := database.GET_GPOcommandByOSandGroup(db, groupName, clientOS)
	if err != nil {
		return "", err
	}
	commands_string := strings.Join(commands, "\n")
	return commands_string, nil
}

// TODO : Send GPO to client
