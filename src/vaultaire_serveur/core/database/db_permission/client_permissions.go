package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
)

func CreateClientPermission(db *sql.DB, permissionName string, isAdmin bool) (int64, error) {
	result, err := db.Exec(`INSERT INTO client_permission (name_permission, is_admin) VALUES (?, ?)`, permissionName, isAdmin)
	if err != nil {
		logs.WriteLog("db", "erreur lors de l'insertion de la permission client CreateClientPermission : "+err.Error())
		return 0, fmt.Errorf("erreur lors de l'insertion de la permission client : %v", err)
	}

	permissionID, err := result.LastInsertId()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la récupération de l'ID de la permission client CreateClientPermission : "+err.Error())
		return 0, fmt.Errorf("erreur lors de la récupération de l'ID de la permission client : %v", err)
	}

	return permissionID, nil
}

// Supprime une permission via son nom
func Command_DELETE_ClientPermissionByName(db *sql.DB, permissionName string) error {
	injection := database.SanitizeIdentifier(permissionName)
	if injection != nil {
		return injection
	}
	// La permission client d'administration n'est pas supprimable.
	if err := database.GuardProtectedClientPermissionDeletion(permissionName); err != nil {
		return err
	}
	query := `DELETE FROM client_permission WHERE name_permission = ?`
	_, err := db.Exec(query, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la suppression de la permission client : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression de la permission client %s : %v", permissionName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Permission client %s supprimée avec succès", permissionName))
	return nil
}

// Command_UPDATE_ClientPermission modifie le drapeau d'administration d'une
// permission client.
//
// Cette fonction manquait : une permission client ne pouvait être que créée ou
// supprimée. Corriger une case cochée par erreur imposait de supprimer la
// permission — donc de la détacher de tous les groupes qui la portaient — puis
// de tout refaire à la main.
//
// Le nom n'est volontairement pas modifiable : il est référencé par
// group_permission_logiciel et le renommer casserait les liaisons existantes.
// Pour renommer, il faut créer une nouvelle permission et rebasculer les
// groupes, ce qui rend le changement visible et réversible.
func Command_UPDATE_ClientPermission(db *sql.DB, permissionName string, isAdmin bool) error {
	if err := database.SanitizeIdentifier(permissionName); err != nil {
		return err
	}

	// La permission client d'administration doit conserver son drapeau : les
	// clients du groupe superadmin en dépendent pour être reconnus comme admin
	// (voir IsUserAdmin). La retirer reviendrait à se verrouiller dehors, de la
	// même façon qu'une suppression — déjà refusée par protected.go.
	if database.IsProtectedClientPermission(permissionName) && !isAdmin {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"protection: tentative de retrait du drapeau admin sur la permission client protégée %q — refusée",
			permissionName))
		return fmt.Errorf(
			"la permission client %q est protégée : son drapeau d'administration ne peut pas être retiré",
			permissionName)
	}

	res, err := db.Exec(
		`UPDATE client_permission SET is_admin = ? WHERE name_permission = ?`,
		isAdmin, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la mise à jour de la permission client : "+err.Error())
		return fmt.Errorf("erreur lors de la mise à jour de la permission client %s : %v", permissionName, err)
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		// Zéro ligne touchée signifie soit une permission inexistante, soit une
		// valeur déjà à l'état demandé. On lève le doute plutôt que de laisser
		// croire à une modification qui n'a pas eu lieu.
		var count int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM client_permission WHERE name_permission = ?`, permissionName,
		).Scan(&count); err == nil && count == 0 {
			return fmt.Errorf("permission client %s introuvable", permissionName)
		}
	}

	logs.Write_Log("INFO", fmt.Sprintf(
		"database: permission client %s mise à jour (admin=%t)", permissionName, isAdmin))
	return nil
}
