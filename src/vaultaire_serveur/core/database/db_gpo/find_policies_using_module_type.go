package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/gpo"
)

// FindPoliciesUsingModuleType retourne les noms des GPO comportant un module de
// ce type. C'est l'intérêt principal du stockage relationnel : pouvoir répondre
// à « qu'est-ce qui touche à sshd dans le domaine ? » avant de valider un
// changement, plutôt que d'inspecter des blobs JSON.
func FindPoliciesUsingModuleType(db *sql.DB, moduleType string) ([]string, error) {
	if _, ok := gpo.SchemaFor(moduleType); !ok {
		return nil, fmt.Errorf("module inconnu : %s", moduleType)
	}
	rows, err := db.Query(
		`SELECT DISTINCT g.gpo_name FROM gpo g
		 INNER JOIN gpo_module m ON m.d_id_gpo = g.id_gpo
		 WHERE m.module_type = ? ORDER BY g.gpo_name`,
		moduleType,
	)
	if err != nil {
		return nil, fmt.Errorf("recherche par type de module impossible : %v", err)
	}
	defer closeRows(rows)

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
