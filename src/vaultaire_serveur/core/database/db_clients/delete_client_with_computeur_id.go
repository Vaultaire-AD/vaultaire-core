package dbclients

import (
	"database/sql"
	"fmt"
	database "vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/logs"
)

// Supprime un client via son computeur_id
func Command_DELETE_ClientWithComputeurID(db *sql.DB, computeurID string) error {
	injection := database.SanitizeIdentifier(computeurID)
	if injection != nil {
		return injection
	}
	query := `DELETE FROM id_logiciels WHERE computeur_id = ?`
	_, err := db.Exec(query, computeurID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la suppression du client : "+err.Error())
		return fmt.Errorf("erreur lors de la suppression du client %s : %v", computeurID, err)
	}

	// Purge du suivi de conformité GPO.
	//
	// Sans elle, une machine mise au rebut resterait indéfiniment dans
	// `vlt gpo status`, souvent en échec, sans qu'aucune action ne puisse la
	// corriger — et un tableau de bord qu'on apprend à ignorer ne sert plus à
	// rien. L'échec n'est PAS remonté : le client est supprimé, c'est ce que
	// l'appelant demandait ; il reste des lignes orphelines, pas une
	// incohérence.
	if err := dbgpo.ForgetCompliance(db, computeurID); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNone,
			"database: suivi de conformité GPO non purgé pour "+computeurID+" : "+err.Error())
	}

	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf("database: Client %s supprimé avec succès", computeurID))
	return nil
}
