package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// GetDomainsByGPO retourne les domaines des groupes liés à une GPO.
//
// C'est la clé de la vérification RBAC : les permissions Vaultaire sont
// exprimées par domaine, donc agir sur une GPO exige d'avoir le droit sur tous
// les domaines qu'elle touche. Une GPO non liée à un groupe ne retourne aucun
// domaine — l'appelant doit alors traiter le cas explicitement plutôt que de
// laisser passer une liste vide comme un blanc-seing.
func GetDomainsByGPO(db *sql.DB, gpoName string) ([]string, error) {
	if err := database.SanitizeIdentifier(gpoName); err != nil {
		return nil, err
	}
	rows, err := db.Query(
		`SELECT DISTINCT dg.domain_name FROM gpo gp
		 INNER JOIN gpo_group gg ON gg.d_id_gpo = gp.id_gpo
		 INNER JOIN groups g ON g.id_group = gg.d_id_group
		 INNER JOIN domain_group dg ON dg.d_id_group = g.id_group
		 WHERE gp.gpo_name = ?`,
		gpoName,
	)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("gpo: lecture des domaines de la GPO %s échouée : %v", gpoName, err))
		return nil, err
	}
	defer closeRows(rows)

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		logs.Write_Log("DEBUG", fmt.Sprintf("gpo: aucun domaine trouvé pour la GPO %s", gpoName))
	}
	return domains, nil
}
