package dbpermission

import (
	"database/sql"
	"vaultaire/core/logs"
)

// Command_GET_Groups_ByUserPermission retourne la liste des noms de groupes
// qui possèdent la permission utilisateur donnée
func Command_GET_Groups_ByUserPermission(db *sql.DB, permissionName string) ([]string, error) {
	query := `
        SELECT DISTINCT g.group_name
        FROM user_permission up
        INNER JOIN group_user_permission gup ON up.id_user_permission = gup.d_id_user_permission
        INNER JOIN groups g ON g.id_group = gup.d_id_group
        WHERE up.name = ?
    `

	rows, err := db.Query(query, permissionName)
	if err != nil {
		logs.WriteLog("db", "Erreur récupération groupes pour permission user '"+permissionName+"' : "+err.Error())
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var groups []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			logs.WriteLog("db", "Erreur scan groupes pour permission user '"+permissionName+"' : "+err.Error())
			return nil, err
		}
		groups = append(groups, g)
	}

	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue ». Sans ce contrôle, une coupure en cours d'itération rend un
	// résultat PARTIEL présenté comme complet.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}
