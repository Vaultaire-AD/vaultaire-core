package commandupdate

import (
	"fmt"
	"vaultaire/core/database"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// update_UserPassword_Command_Parser met a jour le mot de passe d'un utilisateur.
// Format attendu: update -u <username> -p <new_password>
func update_UserPassword_Command_Parser(commandList []string, senderGroupsIDs []int, action, senderUsername string) string {
	if len(commandList) != 4 || commandList[0] != "-u" || commandList[2] != "-p" {
		return "Invalid request. Try 'update -h' for more information."
	}

	targetUsername := commandList[1]
	newPassword := commandList[3]
	if newPassword == "" {
		return "Le mot de passe ne peut pas etre vide."
	}

	db := database.GetDatabase()

	// 1) Recuperer les domaines de l'utilisateur cible pour la verification RBAC.
	targetGroupIDs, err := permission.GetGroupIDsFromUsername(targetUsername)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Echec recuperation groupes de %s : %v", targetUsername, err))
		return fmt.Sprintf("Erreur lors de la recuperation des groupes de %s : %v", targetUsername, err)
	}
	if len(targetGroupIDs) == 0 {
		return fmt.Sprintf("Utilisateur %s introuvable ou sans groupe associe", targetUsername)
	}

	targetDomains, err := permission.GetDomainListsFromGroupIDs(targetGroupIDs)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf("Echec recuperation domaines de %s : %v", targetUsername, err))
		return fmt.Sprintf("Erreur lors de la recuperation des domaines de %s : %v", targetUsername, err)
	}

	ok, reason := permission.CheckPermissionsAllDomains(senderGroupsIDs, action, targetDomains)
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s target=%s reason=%s", senderUsername, action, targetUsername, reason))
		logs.Write_Log("SECURITY", fmt.Sprintf("%s tente de mettre a jour le password de %s (domaines: %v) - %s", senderUsername, targetUsername, targetDomains, reason))
		return fmt.Sprintf("Permission refusee : %s", reason)
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (update password user=%s)", senderUsername, action, targetUsername))

	// 2) Charger l'utilisateur courant puis appliquer la MAJ avec hash/salt via la couche DB.
	targetUserID, err := dbusers.Get_User_ID_By_Username(db, targetUsername)
	if err != nil {
		return fmt.Sprintf("Erreur recuperation ID utilisateur %s : %v", targetUsername, err)
	}

	current, err := dbusers.Command_GET_UserInfo(db, targetUsername)
	if err != nil {
		return fmt.Sprintf("Erreur recuperation infos utilisateur %s : %v", targetUsername, err)
	}

	if err := dbusers.Update_User_Info(db, targetUserID, current.Username, current.Firstname, current.Lastname, newPassword, ""); err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur mise a jour mot de passe pour %s : %v", targetUsername, err))
		return fmt.Sprintf("Erreur mise a jour du mot de passe pour %s : %v", targetUsername, err)
	}

	logs.Write_Log("INFO", fmt.Sprintf("Mot de passe utilisateur %s mis a jour par %s", targetUsername, senderUsername))
	return fmt.Sprintf("Mot de passe de %s mis a jour avec succes", targetUsername)
}
