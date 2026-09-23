package dbsessions

import (
	"database/sql"
	"fmt"

	dbclients "vaultaire/core/database/db_clients"
	dbusers "vaultaire/core/database/db_users"
)

// RafraichirConnexion prolonge la ligne did_login d'un tunnel vivant, et la
// RECRÉE si elle a disparu.
//
// # Pourquoi recréer
//
// Le battement (02_12) ne faisait qu'un UPDATE par clé de session. Or la ligne
// est unique par (compte, machine) et sa clé est réécrite à chaque
// authentification : une connexion secondaire de la machine (le `--fetch-key`
// de sshd) remplaçait la clé du tunnel principal, puis effaçait la ligne en se
// fermant. Le tunnel battait toujours… sans rien trouver à mettre à jour : la
// machine restait absente de `status -c` jusqu'à sa reconnexion complète.
//
// Le battement porte désormais l'identité (compte, machine) et la clé du tunnel
// qui bat : un tunnel vivant est toujours listé, avec sa propre clé.
func RafraichirConnexion(db *sql.DB, username, computeurID string, cleSession []byte) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	idUser, err := dbusers.Get_User_ID_By_Username(db, username)
	if err != nil {
		return fmt.Errorf("battement : compte %s introuvable : %w", username, err)
	}
	idLogiciel, err := dbclients.Get_ClientID_By_ComputerID(db, computeurID)
	if err != nil {
		return fmt.Errorf("battement : machine %s introuvable : %w", computeurID, err)
	}
	validite := EcheanceSession()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM did_login WHERE d_id_user = ? AND d_id_logiciel = ?`,
		idUser, idLogiciel).Scan(&n); err != nil {
		return fmt.Errorf("battement : lecture : %w", err)
	}
	if n > 0 {
		_, err = db.Exec(`UPDATE did_login SET key_time_validity = ?, session_key = ?
			WHERE d_id_user = ? AND d_id_logiciel = ?`, validite, cleSession, idUser, idLogiciel)
		return err
	}
	// Absente : même écriture qu'à l'authentification.
	AddLoginEntry(db, idUser, cleSession, computeurID)
	return nil
}
