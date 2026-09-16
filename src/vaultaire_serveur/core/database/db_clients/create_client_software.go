package dbclients

import (
	"database/sql"
	"errors"
	"fmt"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
)

func Create_ClientSoftware(db *sql.DB, computeurID, logicielType, publicKey string, isServeur bool) error {
	injection := database.SanitizeIdentifier(computeurID, logicielType)
	if injection != nil {
		return injection
	}
	// Vérification si le computeurID existe déjà
	var exists bool
	queryCheck := `SELECT EXISTS(SELECT 1 FROM id_logiciels WHERE computeur_id = ?)`
	err := db.QueryRow(queryCheck, computeurID).Scan(&exists)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors de la vérification de l'existence du computeurID : "+err.Error())
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
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"erreur lors de l'insertion dans la table id_logiciels : "+err.Error())
		return fmt.Errorf("erreur lors de l'insertion dans la table id_logiciels : %v", err)
	}
	logs.Write_LogCode("DEBUG", logs.CodeNone, "database: Nouvelle entrée insérée avec succès dans la base de données.")
	//fmt.Println("Nouvelle entrée insérée avec succès dans la base de données.")
	return nil
}
