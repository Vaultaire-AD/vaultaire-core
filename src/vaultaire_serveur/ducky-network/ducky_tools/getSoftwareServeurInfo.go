package ducky_tools

import (
	"log"
	"strings"
	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	dbsessions "vaultaire/core/database/db_sessions"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func GetSoftwareServeurInformation(trames_content storage.Trames_struct_client) {
	information := strings.Split(trames_content.Content, "\n")
	if len(information) < 4 {
		log.Println("Erreur : données incomplètes dans le contenu GetSoftwareServeurInformation")
		return
	}
	// Les VERSIONS sont facultatives : un agent d'une version antérieure
	// n'envoie que cinq lignes. Elles valent alors la chaîne vide, et la vue
	// affiche « inconnue » — ce qui est l'information qu'on cherche devant un
	// déploiement, et non une erreur.
	versionAgent, versionSDK := VersionsDeLInventaire(information)

	err := dbclients.UpdateHostname(database.GetDatabase(), trames_content.ClientSoftwareID,
		information[0], information[1], information[2], information[3],
		versionAgent, versionSDK)
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de la mise à jour des informations du logiciel serveur : "+err.Error())
		return
	}
	// la il faut gère les session voir la tache sur github
	db := database.GetDatabase()

	// ✅ Mise à jour de key_time_validity

	err = dbsessions.RefreshSessionValidity(db, []byte(trames_content.SessionIntegritykey))
	if err != nil {
		log.Println(err)
	}
}
