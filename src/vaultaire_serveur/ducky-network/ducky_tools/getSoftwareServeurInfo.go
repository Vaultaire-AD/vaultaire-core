package ducky_tools

import (
	"log"
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func GetSoftwareServeurInformation(trames_content storage.Trames_struct_client) {
	information := strings.Split(trames_content.Content, "\n")
	if len(information) < 4 {
		log.Println("Erreur : données incomplètes dans le contenu GetSoftwareServeurInformation")
		return
	}
	err := database.UpdateHostname(database.GetDatabase(), trames_content.ClientSoftwareID, information[0], information[1], information[2], information[3])
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de la mise à jour des informations du logiciel serveur : "+err.Error())
		return
	}
	// la il faut gère les session voir la tache sur github
	db := database.GetDatabase()

	// ✅ Mise à jour de key_time_validity

	err = database.RefreshSessionValidity(db, []byte(trames_content.SessionIntegritykey))
	if err != nil {
		log.Println(err)
	}
}
