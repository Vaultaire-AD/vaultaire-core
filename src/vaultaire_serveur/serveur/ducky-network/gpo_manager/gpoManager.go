package gpomanager

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
)

func GPO_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {

	commands_string, err := Get_GPO_forClient(trames_content.Username, trames_content.ClientSoftwareID)
	if err != nil {
		logs.Write_Log("ERROR", "Error while getting GPO for client "+trames_content.ClientSoftwareID+" : "+err.Error())
		return ("02_16\nserveur_central\n" + trames_content.SessionIntegritykey + "\nfailed to get GPO commands")
	}
	return ("02_16\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + trames_content.Username + "\n" + commands_string)
}
