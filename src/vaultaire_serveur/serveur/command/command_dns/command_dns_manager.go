package commanddns

import (
	dnsdatabase "DUCKY/serveur/dns/DNS_Database"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/permission"
	"fmt"
)

func DNS_Command(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	isactionlegitimate, response := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, action, []string{"*"})
	if !isactionlegitimate {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refusée pour l'utilisateur %s sur l'action %s : %s", sender_Username, action, response))
		return fmt.Sprintf("Permission refusée : %s", response)
	}
	switch command_list[0] {
	case "-h", "help", "--help":
		return `Invalid Request Try get -h for more information 
		or use the following commands:
		create_zone <zone_name>
		get_zone <zone_name>
		add_record <zone_name> <record_type> <name> <value> <ttl>
		get_ptr 
		`
	case "create_zone":
		return command_dns_createNewZone(command_list)
	case "get_zone":
		return command_dns_getZoneInformation_Command_Parser(command_list, dnsdatabase.GetDatabase()) // Remplace nil par ta base de données
	case "add_record":
		return command_dns_addRecord(command_list, dnsdatabase.GetDatabase()) // Remplace nil par ta base de données
	case "get_ptr":
		return command_dns_showReverse(command_list, dnsdatabase.GetDatabase()) // Remplace nil par ta base de données
	case "delete":
		return command_dns_delete(command_list) // Assurez-vous que cette fonction est définie dans votre package
	default:
		return ("Invalid Request Try get -h for more information")
	}
}
