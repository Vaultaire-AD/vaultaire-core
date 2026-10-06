package dbgroups

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	guardprotected "vaultaire/core/database/guard_protected"
	"vaultaire/core/database/schematools"
	"vaultaire/core/logs"
)

// Supprime un groupe via son nom
func Command_DELETE_GroupWithGroupName(db *sql.DB, groupName string) error {
	injection := database.SanitizeIdentifier(groupName)
	if injection != nil {
		return injection
	}
	// Le groupe superadmin n'est pas supprimable : voir protected.go.
	if err := guardprotected.GuardProtectedGroupDeletion(groupName); err != nil {
		return err
	}
	// Les comptes membres vont perdre un `memberOf` sans que leur ligne soit
	// écrite — même raison que côté comptes, à l'autre bout (point 126).
	if idGroupe, err := groupIDParNom(db, groupName); err == nil {
		schematools.ToucherVoisinsAvantSuppression(db, schematools.TableGroupes, idGroupe)
	} else {
		logs.Write_Log("WARNING", "database: identifiant du groupe "+groupName+
			" illisible avant suppression, ses membres garderont un memberOf fantôme "+
			"dans les synchronisations incrémentales : "+err.Error())
	}

	query := `DELETE FROM groups WHERE group_name = ?`
	_, err := db.Exec(query, groupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la suppression du groupe : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression du groupe %s : %v", groupName, err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Groupe %s supprimé avec succès", groupName))
	return nil
}

// groupIDParNom rend l'identifiant d'un groupe.
//
// Une lecture de plus avant la suppression, uniquement pour pouvoir prévenir les
// membres que leur appartenance a changé. Le groupe est supprimé même si elle
// échoue : perdre une date de modification dégrade une synchronisation, refuser
// la suppression casserait une opération d'administration.
func groupIDParNom(db *sql.DB, groupName string) (int, error) {
	var id int
	err := db.QueryRow(`SELECT id_group FROM groups WHERE group_name = ?`, groupName).Scan(&id)
	return id, err
}
