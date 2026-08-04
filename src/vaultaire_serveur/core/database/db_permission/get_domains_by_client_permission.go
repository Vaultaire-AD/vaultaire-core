package dbpermission

import (
	"database/sql"
	"vaultaire/core/logs"
)

// ---- Récupérer les domaines d'une permission client ----
func Command_GET_Domains_ByClientPermission(db *sql.DB, permissionName string) ([]string, error) {
	query := `
		SELECT DISTINCT dg.domain_name
		FROM client_permission cp
		INNER JOIN group_permission_logiciel gpl ON cp.id_permission = gpl.d_id_permission
		INNER JOIN groups g ON g.id_group = gpl.d_id_group
		INNER JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE cp.name_permission = ?
	`

	rows, err := db.Query(query, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur lors de la récupération des domaines pour la permission client '"+permissionName+"' : "+err.Error())
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.WriteLog("db", "Erreur lors de la fermeture du rows: "+err.Error())
		}
	}()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			logs.WriteLog("db", "Erreur lors du scan des domaines pour la permission client '"+permissionName+"' : "+err.Error())
			return nil, err
		}
		domains = append(domains, domain)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}
