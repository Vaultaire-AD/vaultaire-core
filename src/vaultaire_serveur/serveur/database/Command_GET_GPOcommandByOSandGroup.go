package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"strings"
)

func GET_GPOcommandByOSandGroup(db *sql.DB, groupName, osName string) ([]string, error) {
	injection := SanitizeInput(groupName, osName)
	if injection != nil {
		return nil, injection
	}

	// Requête pour récupérer toutes les GPOs liées au groupe
	query := `
			SELECT 
				gpo.gpo_name,
				gpo.ubuntu,
				gpo.debian,
				gpo.rocky
			FROM groups g
			LEFT JOIN group_linux_gpo gg ON g.id_group = gg.d_id_group
			LEFT JOIN linux_gpo_distributions gpo ON gg.d_id_gpo = gpo.id
			WHERE g.group_name = ?
		`
	rows, err := db.Query(query, groupName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération des GPOs: "+err.Error())
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	var commands []string
	for rows.Next() {
		var gpoName, ubuntuCmd, debianCmd, rockyCmd string
		if err := rows.Scan(&gpoName, &ubuntuCmd, &debianCmd, &rockyCmd); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des GPOs: "+err.Error())
			return nil, err
		}

		var cmd string
		switch strings.ToLower(osName) {
		case "ubuntu":
			cmd = ubuntuCmd
		case "debian":
			cmd = debianCmd
		case "rocky", "centos", "redhat":
			cmd = rockyCmd
		default:
			logs.WriteLog("db", "OS non supporté: "+osName)
			cmd = ""
		}

		if cmd != "" {
			commands = append(commands, cmd)
		} else {
			logs.WriteLog("db", "Pas de commande trouvée pour GPO "+gpoName+" sur OS "+osName)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return commands, nil
}
