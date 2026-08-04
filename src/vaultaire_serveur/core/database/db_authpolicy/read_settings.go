package dbauthpolicy

import (
	"database/sql"
)

// readSettings récupère plusieurs clés en une requête.
func readSettings(db *sql.DB, keys ...string) (map[string]string, error) {
	out := make(map[string]string, len(keys))
	if len(keys) == 0 {
		return out, nil
	}

	query := "SELECT setting_key, setting_value FROM server_settings WHERE setting_key IN (?"
	args := make([]any, 0, len(keys))
	args = append(args, keys[0])
	for _, k := range keys[1:] {
		query += ",?"
		args = append(args, k)
	}
	query += ")"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	// rows.Err distingue « plus de lignes » d'une rupture en cours de parcours :
	// sans ce contrôle, une lecture interrompue passerait pour une table vide,
	// donc pour une politique désactivée.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
