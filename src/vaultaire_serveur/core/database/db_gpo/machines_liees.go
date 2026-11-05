package dbgpo

import (
	"database/sql"
	"fmt"
)

// MachinesLieesA rend les identifiants des machines qui reçoivent une GPO :
// celles des groupes auxquels elle est liée — TO-DO 169.
//
// Sans doublon : une machine présente dans deux groupes liés n'y figure qu'une
// fois, sans quoi une demande de cycle lui serait faite deux fois.
//
// C'est le parc INSCRIT, pas le parc joignable : une machine éteinte y figure.
// C'est à l'appelant de dire ce qu'il a pu joindre.
func MachinesLieesA(db *sql.DB, policyID int) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("gpo: connexion base indisponible")
	}
	rows, err := db.Query(
		`SELECT DISTINCT l.computeur_id
		   FROM gpo_group gg
		   JOIN logiciel_group lg ON lg.d_id_group = gg.d_id_group
		   JOIN id_logiciels l ON l.id_logiciel = lg.d_id_logiciel
		  WHERE gg.d_id_gpo = ?
		  ORDER BY l.computeur_id`, policyID)
	if err != nil {
		return nil, fmt.Errorf("lecture des machines de la GPO %d : %w", policyID, err)
	}
	defer closeRows(rows)

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
