package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
)

type GroupInfo struct {
	ID         int
	Name       string
	DomainName string
}

// Récupère le nom de groupe + le domaine associé
func GetGroupInfoByID(db *sql.DB, groupID int) (*GroupInfo, error) {
	var gi GroupInfo

	query := `
        SELECT g.id_group, g.group_name, dg.domain_name
        FROM groups g
        LEFT JOIN domain_group dg ON dg.d_id_group = g.id_group
        WHERE g.id_group = ?
        LIMIT 1;
    `

	err := db.QueryRow(query, groupID).Scan(&gi.ID, &gi.Name, &gi.DomainName)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("aucun groupe trouvé pour l'ID %d", groupID)
		}
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur GetGroupInfoByID: %v", err))
		return nil, err
	}

	return &gi, nil
}
