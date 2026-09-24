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

	// Le tunnel machine (`vaultaire`) rafraîchit — et recrée au besoin — la
	// ligne de SA machine : voir RafraichirConnexion. L'identité a été
	// comparée à celle de la session par Split_Action avant d'arriver ici.
	if trames_content.Username == "vaultaire" && trames_content.ClientSoftwareID != "" {
		err = dbsessions.RafraichirConnexion(db, trames_content.Username,
			trames_content.ClientSoftwareID, []byte(trames_content.SessionIntegritykey))

		// Le battement de la machine prolonge aussi les sessions de SES
		// utilisateurs, dans leur propre table.
		//
		// Une session ouverte par PAM n'a ni connexion ni clé propre : elle vit
		// dans ce tunnel-ci (trame 03_01). Rien ne peut donc la prolonger
		// d'elle-même, et sans cette ligne toute personne connectée
		// disparaîtrait de `status -u` au bout de dix minutes alors qu'elle est
		// devant son écran.
		//
		// La contrepartie est voulue : si la machine s'éteint, elle cesse de
		// battre, et ses sessions utilisateur expirent avec elle. C'est le seul
		// mécanisme d'expiration qu'elles aient.
		//
		// La prolongation ne touche QUE `user_sessions` : étendue à `did_login`,
		// elle maintiendrait en vie les lignes fantômes écrites par la première
		// version du point 68, qu'on laisse justement expirer.
		if _, errS := dbsessions.ProlongerSessionsUtilisateurDeLaMachine(db, trames_content.ClientSoftwareID); errS != nil {
			logs.Write_LogCode("WARNING", logs.CodeDBQuery,
				"battement: sessions utilisateur non prolongées sur "+
					trames_content.ClientSoftwareID+" : "+errS.Error())
		}
	} else {
		err = dbsessions.RefreshSessionValidity(db, []byte(trames_content.SessionIntegritykey))
	}
	if err != nil {
		log.Println(err)
	}
}
