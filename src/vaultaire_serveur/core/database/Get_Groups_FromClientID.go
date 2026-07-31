package database

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// Command_GET_GroupIDsFromClientID récupère tous les IDs de groupes liés à un client.
//
// clientID est un id_logiciel, pas un id_group : le filtre porte donc sur
// lg.d_id_logiciel. La version précédente filtrait sur lg.d_id_group, ce qui
// retournait le groupe dont l'identifiant coïncidait avec celui du client —
// donc presque toujours un seul groupe, et le plus souvent le mauvais. Le défaut
// passait inaperçu tant que le client avait peu de groupes et un identifiant bas.
//
// Impacts corrigés : résolution des GPO machine, intersection des groupes en
// scope user, et résolution des domaines d'un client pour les contrôles RBAC.
func Command_GET_GroupIDsFromClientID(db *sql.DB, clientID int) ([]int, error) {
	query := `
		SELECT g.id_group
		FROM groups g
		JOIN logiciel_group lg ON lg.d_id_group = g.id_group
		WHERE lg.d_id_logiciel = ?
		ORDER BY g.id_group;
	`
	rows, err := db.Query(query, clientID)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur Command_GET_GroupIDsFromClientID: %v", err))
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.Write_Log("ERROR", "Erreur fermeture curseur Command_GET_GroupIDsFromClientID: "+err.Error())
		}
	}()

	var groupIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lecture row Command_GET_GroupIDsFromClientID: %v", err))
			continue
		}
		groupIDs = append(groupIDs, id)
	}
	// Sans ce contrôle, une erreur survenue en cours d'itération retournerait une
	// liste tronquée sans le signaler : le client se verrait appliquer les GPO
	// d'une partie seulement de ses groupes, silencieusement.
	if err := rows.Err(); err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur parcours Command_GET_GroupIDsFromClientID: %v", err))
		return nil, err
	}
	return groupIDs, nil
}
