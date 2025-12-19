package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
)

// Command_GET_GroupIDsFromClientID récupère tous les IDs de groupes liés à un client
func Command_GET_GroupIDsFromClientID(db *sql.DB, clientID int) ([]int, error) {
	query := `
		SELECT g.id_group
		FROM groups g
		JOIN logiciel_group lg ON lg.d_id_group = g.id_group
		WHERE lg.d_id_group = ?;
	`
	rows, err := db.Query(query, clientID)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur Command_GET_GroupIDsFromClientID: %v", err))
		return nil, err
	}
	defer rows.Close()

	var groupIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lecture row Command_GET_GroupIDsFromClientID: %v", err))
			continue
		}
		groupIDs = append(groupIDs, id)
	}
	return groupIDs, nil
}
