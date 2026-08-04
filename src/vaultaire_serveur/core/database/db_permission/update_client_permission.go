package dbpermission

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
)

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
	if isprotected.IsProtectedClientPermission(permissionName) && !isAdmin {
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
