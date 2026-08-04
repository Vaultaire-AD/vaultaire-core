package dbclients

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

// Command_Remove_SoftwareFromGroup supprime un logiciel d'un groupe
func Command_Remove_SoftwareFromGroup(db *sql.DB, computeur_id, groupName string) error {
	injection := database.SanitizeIdentifier(computeur_id, groupName)
	if injection != nil {
		return injection
	}
	// Vérifier si le logiciel existe
	logicielID, found, err := database.LookupClientID(db, computeur_id)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération du logiciel : %v", err))
		return fmt.Errorf("erreur lors de la récupération du logiciel : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: Logiciel avec computeur_id %s introuvable", computeur_id))
		return fmt.Errorf("logiciel avec computeur_id %s introuvable", computeur_id)
	}

	// Vérifier si le groupe existe
	groupID, found, err := database.LookupGroupID(db, groupName)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la récupération du groupe : %v", err))
		return fmt.Errorf("erreur lors de la récupération du groupe : %v", err)
	}
	if !found {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: Groupe %s introuvable", groupName))
		return fmt.Errorf("groupe %s introuvable", groupName)
	}

	// Vérifier si le logiciel est dans ce groupe
	member, err := clientGroupLinkExists(db, logicielID, groupID)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la vérification du logiciel dans le groupe : %v", err))
		return fmt.Errorf("erreur lors de la vérification du logiciel dans le groupe : %v", err)
	}

	if !member {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, fmt.Sprintf("database: Le logiciel %s ne fait pas partie du groupe %s", computeur_id, groupName))
		return fmt.Errorf("le logiciel %s ne fait pas partie du groupe %s", computeur_id, groupName)
	}

	// Supprimer le logiciel du groupe
	queryRemove := `DELETE FROM logiciel_group WHERE d_id_logiciel = ? AND d_id_group = ?`
	_, err = db.Exec(queryRemove, logicielID, groupID)
	if err != nil {
		logs.WriteLog("db", fmt.Sprintf("Erreur lors de la suppression du logiciel du groupe : %v", err))
		return fmt.Errorf("erreur lors de la suppression du logiciel du groupe : %v", err)
	}

	// Log de succès
	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Logiciel %s retiré du groupe %s", computeur_id, groupName))

	return nil
}
