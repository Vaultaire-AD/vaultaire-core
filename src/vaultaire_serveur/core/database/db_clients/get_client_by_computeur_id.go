package dbclients

import (
	"database/sql"
	"fmt"
	"strings"
	database "vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

func Command_GET_ClientByComputeurID(db *sql.DB, computeurID string) (*storage.Software, error) {
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return nil, err
	}

	query := `
SELECT 
    l.id_logiciel, 
    l.logiciel_type, 
    l.computeur_id, 
    l.hostname, 
    l.serveur, 
    l.processeur, 
    l.ram, 
    l.os,
    COALESCE(GROUP_CONCAT(DISTINCT g.group_name SEPARATOR ', '), '') AS groups,
    COALESCE(GROUP_CONCAT(DISTINCT p.name_permission SEPARATOR ', '), '') AS permissions
FROM 
    id_logiciels l
LEFT JOIN 
    logiciel_group lg ON l.id_logiciel = lg.d_id_logiciel
LEFT JOIN 
    groups g ON lg.d_id_group = g.id_group
LEFT JOIN 
    group_permission_logiciel lp ON lg.d_id_group = lp.d_id_group
LEFT JOIN 
    client_permission p ON lp.d_id_permission = p.id_permission
WHERE 
    l.computeur_id = ?
GROUP BY 
    l.id_logiciel
`

	row := db.QueryRow(query, computeurID)

	var software storage.Software
	var groups, permissions string

	err := row.Scan(
		&software.ID,
		&software.LogicielType,
		&software.ComputeurID,
		&software.Hostname,
		&software.Serveur,
		&software.Processeur,
		&software.RAM,
		&software.OS,
		&groups,
		&permissions,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("❌ Aucun client trouvé avec le Computeur ID: %s", computeurID)
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la récupération du client : "+err.Error())
		return nil, fmt.Errorf("❌ Erreur lors de la récupération du client : %v", err)
	}

	// Transformer les chaînes séparées en slices, en évitant les éléments vides
	if groups == "" {
		software.Groups = []string{}
	} else {
		software.Groups = strings.Split(groups, ", ")
	}

	if permissions == "" {
		software.Permissions = []string{}
	} else {
		software.Permissions = strings.Split(permissions, ", ")
	}

	return &software, nil
}
