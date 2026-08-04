package dbclients

import (
	"database/sql"
	"strconv"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

func UpdateHostname(db *sql.DB, computeurID, hostname, os, ram, proc string) error {
	// L'identifiant machine nomme une entité : liste blanche. Les informations
	// matérielles sont du texte libre — « Intel(R) Core(TM) i7 », « Ubuntu 22.04
	// LTS » — et ne passeraient pas une liste blanche d'identifiant.
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return err
	}
	injection := database.SanitizeInput(hostname, os, ram, proc)
	if injection != nil {
		return injection
	}
	proccesseur, _ := strconv.Atoi(proc)
	query := `
	UPDATE id_logiciels
	SET
    	hostname = ?,
    	processeur = ?,
    	ram = ?,
    	os = ?
	WHERE computeur_id = ?;
	`

	result, err := db.Exec(query, hostname, proccesseur, ram, os, computeurID)
	if err != nil {
		logs.WriteLog("db", "erreur lors de la mise à jour UpdateHostname : "+err.Error())
	}

	// Vérifier combien de lignes ont été affectées
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logs.WriteLog("db", "erreur lors de la récupération du nombre de lignes affectées UpdateHostname :"+err.Error())
	}
	if rowsAffected == 0 {
		// logs.WriteLog("db", "aucune ligne mise à jour, vérifiez computeur_id UpdateHostname")
		return nil
	}
	// logs.WriteLog("db", "Mise à jour réussie : "+strconv.FormatInt(rowsAffected, 10)+" ligne(s) affectée(s) UpdateHostname")
	return nil
}
