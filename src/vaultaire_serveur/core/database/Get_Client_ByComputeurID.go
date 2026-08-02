package database

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// Get_ClientID_By_ComputerID récupère l'id_logiciel d'un client depuis son
// computeur_id.
//
// La version précédente sélectionnait d_id_group en passant par logiciel_group :
// elle retournait donc un identifiant de GROUPE sous le nom de clientID. Le
// défaut se compensait avec celui de Command_GET_GroupIDsFromClientID, qui
// filtrait lui aussi sur la colonne groupe — le couple rendait exactement un
// groupe, toujours le même, et paraissait fonctionner tant qu'un client n'avait
// qu'un seul groupe.
//
// Deux conséquences corrigées ici :
//   - la lecture part de id_logiciels, donc l'identifiant retourné est bien
//     celui du client ;
//   - un client n'appartenant à aucun groupe est désormais trouvé. L'ancienne
//     jointure sur logiciel_group le faisait passer pour inexistant, alors qu'un
//     client sans groupe est un état normal juste après sa création.
func Get_ClientID_By_ComputerID(db *sql.DB, computerID string) (int, error) {
	if err := SanitizeIdentifier(computerID); err != nil {
		return 0, err
	}

	var clientID int
	query := `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ? LIMIT 1;`

	err := db.QueryRow(query, computerID).Scan(&clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("aucun client trouvé pour l'ordinateur %s", computerID)
		}
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur Get_ClientID_By_ComputerID: %v", err))
		return 0, err
	}
	return clientID, nil
}
