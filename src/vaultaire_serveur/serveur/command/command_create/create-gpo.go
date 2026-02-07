package commandcreate

import (
	"vaultaire/serveur/command/display"
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"fmt"
)

// create_GPO handles the creation of a Group Policy Object (GPO).
// It expects a command list with the format: ["-gpo", "gpo_name", "--cmd", "command"] or ["-gpo", "gpo_name", "--ubuntu", "command", "--debian", "command", "--rocky", "command"].
// If the command is valid, it creates the GPO and returns its details.
// If the command is invalid or an error occurs, it logs the error and returns an error message.
// It also prints the command list for debugging purposes.
// Example usage:
// create_GPO([]string{"-gpo", "exampleGPO", "--cmd", "exampleCommand"})
// create_GPO([]string{"-gpo", "exampleGPO", "--ubuntu", "ubuntuCommand", "--debian", "debianCommand", "--rocky", "rockyCommand"})
func create_GPO(command_list []string) string {
	if len(command_list) < 2 {
		return "Erreur : -gpo <nom_de_la_gpo> [--cmd <commande>] ou [--ubuntu ... --debian ...]"
	}
	fmt.Println("Command list:")
	for i, arg := range command_list {
		fmt.Printf("  [%d] %s\n", i, arg)
	}

	gpoName := command_list[1]
	ubuntu := ""
	debian := ""
	rocky := ""

	// Parser les arguments
	for i := 2; i < len(command_list); i++ {
		switch command_list[i] {
		case "--cmd":
			if i+1 < len(command_list) {
				ubuntu = command_list[i+1]
				debian = command_list[i+1]
				rocky = command_list[i+1]
			}
		case "--ubuntu":
			if i+1 < len(command_list) {
				ubuntu = command_list[i+1]
				i++
			}
		case "--debian":
			if i+1 < len(command_list) {
				debian = command_list[i+1]
				i++
			}
		case "--rocky":
			if i+1 < len(command_list) {
				rocky = command_list[i+1]
				i++
			}
		}
	}

	if ubuntu == "" && debian == "" && rocky == "" {
		return "Erreur : aucune commande spécifiée pour la GPO"
	}

	_, err := database.CreateGPO(database.GetDatabase(), gpoName, ubuntu, debian, rocky)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la création de la GPO "+gpoName+" : "+err.Error())
		return (">> -" + err.Error())
	}

	logs.Write_Log("INFO", "GPO créée avec succès : "+gpoName)
	gpoDetails, err := database.Command_GET_GPOInfoByName(database.GetDatabase(), gpoName)
	if err != nil {
		logs.Write_Log("WARNING", "Erreur lors de la récupération des détails de la GPO "+gpoName+" : "+err.Error())
		return (">> -" + err.Error())
	}

	return display.DisplayGPOByName(&gpoDetails)
}
