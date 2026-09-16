package dbgpo

import (
	"database/sql"
	"fmt"
)

// findModulesUsingValue retourne les GPO dont un module utilise cette valeur.
//
// Les paramètres sont stockés en JSON : la recherche se fait sur le motif
// "field":"value", ce qui est exact pour des noms sans caractère spécial (le
// format des noms de définition l'impose déjà).
func findModulesUsingValue(db *sql.DB, moduleType, fieldName, value string) ([]string, error) {
	needle := `"` + fieldName + `":"` + value + `"`
	rows, err := db.Query(
		`SELECT DISTINCT g.gpo_name FROM gpo g
		 INNER JOIN gpo_module m ON m.d_id_gpo = g.id_gpo
		 WHERE m.module_type = ? AND m.params LIKE CONCAT('%', ?, '%')
		 ORDER BY g.gpo_name`,
		moduleType, needle)
	if err != nil {
		return nil, fmt.Errorf("recherche des utilisateurs de %q impossible : %v", value, err)
	}
	defer closeRows(rows)

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
