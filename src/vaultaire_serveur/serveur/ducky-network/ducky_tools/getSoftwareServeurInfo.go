package ducky_tools

import (
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"log"
	"strconv"
	"strings"
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

	// Supposons que tu as une fonction pour récupérer l'ID utilisateur à partir du username
	userID, err := database.Get_User_ID_By_Username(db, trames_content.Username)
	if err != nil {
		log.Printf("❌ Impossible de trouver l'ID utilisateur pour %s: %v\n", trames_content.Username, err)
		return
	}
	// ✅ Mise à jour de key_time_validity
	softwareID, _ := strconv.Atoi(trames_content.ClientSoftwareID)
	err = database.UpdateSessionKeyValidity(db, userID, softwareID)
	if err != nil {
		log.Println(err)
	}
}
