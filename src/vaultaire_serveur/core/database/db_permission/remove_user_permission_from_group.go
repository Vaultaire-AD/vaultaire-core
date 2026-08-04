package dbpermission

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	guardprotected "vaultaire/core/database/guard_protected"
	"vaultaire/core/logs"
)

// Command_Remove_UserPermissionFromGroup retire une permission UTILISATEUR d'un
// groupe.
//
// CETTE FONCTION N'A JAMAIS FONCTIONNÉ, sur deux défauts distincts, trouvés en
// redirigeant les résolutions d'identifiant recopiées (TO-DO_Database §2.2) :
//
//  1. Elle résolvait le nom de la permission dans client_permission, la table
//     des permissions CLIENT. Les deux familles sont numérotées séparément :
//     l'identifiant obtenu ne désignait donc pas la permission demandée, quand
//     il existait.
//  2. Elle interrogeait puis supprimait dans group_permission_user, une table
//     qui n'existe pas — le schéma déclare group_user_permission, avec la
//     colonne d_id_user_permission. MySQL rendait « table inconnue » dès le
//     COUNT, et la fonction retournait « erreur lors de la vérification de la
//     permission du groupe ».
//
// Conséquence : retirer une permission utilisateur d'un groupe échouait par les
// deux chemins offerts, `vlt remove -g <groupe> -pu <permission>` et le bouton
// de la page groupe. En web l'appelant ne teste que « == nil », donc le clic ne
// produisait aucun message : l'administrateur voyait la permission rester en
// place sans explication. Un droit accordé ne pouvait plus être repris, ce qui
// en fait un défaut de sécurité et pas seulement une gêne — le contournement
// était de supprimer la permission entière, donc de la retirer à TOUS les
// groupes.
//
// Même famille de faute que DeleteGroup (§1.4), qui visait elle aussi des tables
// inexistantes : du code jamais exécuté sur une vraie base.
func Command_Remove_UserPermissionFromGroup(db *sql.DB, groupName, permissionName string) error {
	injection := database.SanitizeIdentifier(groupName, permissionName)
	if injection != nil {
		return injection
	}
	// Dernier maillon de la chaîne d'accès administrateur : voir protected.go.
	if err := guardprotected.GuardProtectedUserPermissionUnlink(groupName, permissionName); err != nil {
		return err
	}

	// Vérifier si le groupe existe
	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		return fmt.Errorf("groupe %s introuvable", groupName)
	}

	// Vérifier si la permission existe (user_permission, pas client_permission)
	permissionID, found, err := database.LookupUserPermissionID(db, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération de la permission : "+err.Error())
		return fmt.Errorf("erreur lors de la récupération de la permission : %v", err)
	}
	if !found {
		return fmt.Errorf("permission %s introuvable", permissionName)
	}

	// Vérifier si la permission est bien attribuée au groupe
	var count int
	queryCheck := `SELECT COUNT(*) FROM group_user_permission WHERE d_id_group = ? AND d_id_user_permission = ?`
	err = db.QueryRow(queryCheck, groupID, permissionID).Scan(&count)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la vérification de la permission du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification de la permission du groupe : %v", err)
	}

	if count == 0 {
		return fmt.Errorf("le groupe %s ne possède pas la permission %s", groupName, permissionName)
	}

	// Supprimer la permission du groupe
	queryRemove := `DELETE FROM group_user_permission WHERE d_id_group = ? AND d_id_user_permission = ?`
	_, err = db.Exec(queryRemove, groupID, permissionID)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de la permission : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de la permission : %v", err)
	}

	logs.Write_LogCode("DEBUG", logs.CodeNone,
		fmt.Sprintf("database: permission utilisateur %s retirée du groupe %s", permissionName, groupName))
	return nil
}
