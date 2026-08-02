package commanddelete

import (
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// delete_users_Command_Parser supprime un utilisateur par son nom.
// Format attendu : ["-u", "username"]
// Vérifie les permissions sur le domaine du groupe auquel appartient l'utilisateur.
func delete_users_Command_Parser(command_list []string, sender_groupsIDs []int, action, sender_Username string) string {
	db := database.GetDatabase()

	// Vérification syntaxe
	if len(command_list) != 2 || command_list[0] != "-u" {
		return "Invalid request. Try 'delete -h' for more information."
	}

	username := command_list[1]

	// 🔹 Étape 1 : Récupération du domaine de l’utilisateur cible
	userGroups, err := permission.GetGroupIDsFromUsername(username)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Échec récupération groupes de %s : %v", username, err))
		return fmt.Sprintf("Erreur lors de la récupération des groupes de %s : %v", username, err)
	}
	if len(userGroups) == 0 {
		return fmt.Sprintf("Utilisateur %s introuvable ou sans groupe associé", username)
	}

	// 🔹 Étape 2 : Récupération des domaines associés aux groupes de l’utilisateur
	domains, err := permission.GetDomainListsFromGroupIDs(userGroups)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Erreur récupération domaines de %s : %v", username, err))
		return fmt.Sprintf("Erreur lors de la récupération des domaines de %s : %v", username, err)
	}

	// 🔹 Étape 3 : Vérification de permission sur les domaines concernés
	ok, reason := permission.CheckPermissionsAllDomains(sender_groupsIDs, action, domains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s target=%s reason=%s", sender_Username, action, username, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("Suppression refusée : %s tente de supprimer %s (domaines : %v) — %s", sender_Username, username, domains, reason))
		return fmt.Sprintf("Permission refusée : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (delete user)", sender_Username, action))

	// 🔹 Étape 4 : Suppression sécurisée
	err = database.Command_DELETE_UserWithUsername(db, username)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur suppression utilisateur %s : %v", username, err))
		return fmt.Sprintf("Erreur lors de la suppression de l'utilisateur %s : %v", username, err)
	}

	logs.Write_Log("INFO", fmt.Sprintf("Utilisateur %s supprimé avec succès par %s", username, sender_Username))
	return fmt.Sprintf("Utilisateur %s supprimé avec succès", username)
}
