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

	// Une seule écriture, qui prolonge OU recrée.
	//
	// C'était COUNT(*) puis UPDATE, puis un AddLoginEntry si le compte était à
	// zéro : trois allers-retours, et une course entre la lecture et l'écriture.
	// Deux battements simultanés de la même machine — le tunnel et une
	// connexion du « --fetch-key » de sshd — y trouvaient tous les deux « la
	// ligne n'existe pas » et en inséraient chacun une.
	//
	// Depuis le TO-DO 107, l'unicité (compte, machine) est portée par la base :
	// ON DUPLICATE KEY UPDATE fait les deux cas en une requête, et c'est MySQL
	// qui tranche.
	if _, err := db.Exec(`
		INSERT INTO did_login (d_id_user, session_key, key_time_validity, d_id_logiciel)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			session_key       = VALUES(session_key),
			key_time_validity = VALUES(key_time_validity)`,
		idUser, cleSession, validite, idLogiciel); err != nil {
		return fmt.Errorf("battement : enregistrement : %w", err)
	}
	return nil
}
