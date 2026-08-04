package dbsessions

import (
	"database/sql"
	"fmt"
	"log"
	database "vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/logs"
)

func DeleteDidLogin(db *sql.DB, Username string, computeurID string) error {
	injection := database.SanitizeIdentifier(computeurID, Username)
	if injection != nil {
		return injection
	}
	// Les deux identifiants passent par les helpers dédiés, et leurs erreurs
	// sont remontées.
	//
	// Elles étaient ignorées — `idUser, _ :=` — ce qui envoyait un 0 dans le
	// DELETE quand le compte ou la machine n'existait plus. La requête ne
	// supprimait alors rien, la fonction retournait nil, et l'appelant croyait
	// la ligne de connexion nettoyée. Le seul indice était un log « Aucune ligne
	// supprimée » noyé dans la sortie standard.
	//
	// Get_ClientID_By_ComputerID remplace GetIdLogicielByComputeurID, qui posait
	// exactement la même requête pour retourner la même colonne en `string` au
	// lieu d'`int`. Deux fonctions pour une question, avec deux types : c'est ce
	// qui obligeait le reste du code à convertir dans un sens ou dans l'autre
	// selon l'endroit.
	idUser, err := dbusers.Get_User_ID_By_Username(db, Username)
	if err != nil {
		return fmt.Errorf("suppression de la session : utilisateur %s introuvable : %w", Username, err)
	}
	idLogiciel, err := dbclients.Get_ClientID_By_ComputerID(db, computeurID)
	if err != nil {
		return fmt.Errorf("suppression de la session : machine %s introuvable : %w", computeurID, err)
	}

	query := "DELETE FROM did_login WHERE d_id_user = ? AND d_id_logiciel = ?"
	stmt, err := db.Prepare(query)
	if err != nil {
		return fmt.Errorf("erreur de préparation de la requête : %w", err)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	result, err := stmt.Exec(idUser, idLogiciel)
	if err != nil {
		return fmt.Errorf("erreur lors de l'exécution de la requête : %w", err)
	}

	raffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("erreur lors de la récupération des lignes affectées : %w", err)
	}

	if raffected == 0 {
		log.Println("Aucune ligne supprimée, vérifiez les valeurs de id_user et id_logiciel")
	} else {
		log.Printf("%d ligne(s) supprimée(s)\n", raffected)
	}

	return nil
}
