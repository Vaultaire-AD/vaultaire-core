package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"vaultaire/core/logs"
)

func Create_ClientSoftware(db *sql.DB, computeurID, logicielType, publicKey string, isServeur bool) error {
	injection := SanitizeIdentifier(computeurID, logicielType)
	if injection != nil {
		return injection
	}
	// Vérification si le computeurID existe déjà
	var exists bool
	queryCheck := `SELECT EXISTS(SELECT 1 FROM id_logiciels WHERE computeur_id = ?)`
	err := db.QueryRow(queryCheck, computeurID).Scan(&exists)
	if err != nil {
		logs.WriteLog("db", "erreur lors de la vérification de l'existence du computeurID : "+err.Error())
		return fmt.Errorf("erreur lors de la vérification de l'existence du computeurID : %v", err)
	}

	if exists {
		logs.Write_LogCode("WARNING", logs.CodeDBGeneric, "database: le computeurID existe déjà dans la base de données")
		return errors.New("le computeurID existe déjà dans la base de données")
	}

	// Insertion de la nouvelle entrée
	queryInsert := `
	INSERT INTO id_logiciels (public_key, logiciel_type, computeur_id, hostname, serveur, processeur, ram, os)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = db.Exec(queryInsert, publicKey, logicielType, computeurID, "default", isServeur, 0, "0Go", "Linux")

	if err != nil {
		logs.WriteLog("db", "erreur lors de l'insertion dans la table id_logiciels : "+err.Error())
		return fmt.Errorf("erreur lors de l'insertion dans la table id_logiciels : %v", err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Nouvelle entrée insérée avec succès dans la base de données.")
	//fmt.Println("Nouvelle entrée insérée avec succès dans la base de données.")
	return nil
}

func UpdateHostname(db *sql.DB, computeurID, hostname, os, ram, proc string) error {
	// L'identifiant machine nomme une entité : liste blanche. Les informations
	// matérielles sont du texte libre — « Intel(R) Core(TM) i7 », « Ubuntu 22.04
	// LTS » — et ne passeraient pas une liste blanche d'identifiant.
	if err := SanitizeIdentifier(computeurID); err != nil {
		return err
	}
	injection := SanitizeInput(hostname, os, ram, proc)
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
