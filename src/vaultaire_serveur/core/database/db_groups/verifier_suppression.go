package dbgroups

import (
	"database/sql"
	"fmt"
	"strings"

	"vaultaire/core/domainname"
)

// VerifierSuppressionSansOrphelin refuse de supprimer le DERNIER groupe d'un
// domaine qui a des sous-domaines.
//
// Un domaine n'existe que porté par un groupe. Supprimer le seul groupe de
// `acme.lan` alors que `infra.acme.lan` existe ferait disparaître `acme.lan`
// sous ses enfants : l'état que CreateGroupAvecParents évite à la création.
//
// Un groupe inexistant n'est pas refusé ici : la suppression dira elle-même
// qu'il n'existe pas.
func VerifierSuppressionSansOrphelin(db *sql.DB, groupName string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	var domaine string
	err := db.QueryRow(`SELECT dg.domain_name FROM domain_group dg
		JOIN groups g ON g.id_group = dg.d_id_group WHERE g.group_name = ?`, groupName).Scan(&domaine)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lecture du domaine du groupe %s : %w", groupName, err)
	}
	domaine = domainname.NormaliserDomaine(domaine)
	if domaine == "" {
		return nil
	}

	var autres int
	if err := db.QueryRow(`SELECT COUNT(*) FROM domain_group dg JOIN groups g ON g.id_group = dg.d_id_group
		WHERE LOWER(dg.domain_name) = ? AND g.group_name <> ?`, domaine, groupName).Scan(&autres); err != nil {
		return fmt.Errorf("lecture du domaine %s : %w", domaine, err)
	}
	if autres > 0 {
		return nil
	}

	rows, err := db.Query(`SELECT DISTINCT LOWER(domain_name) FROM domain_group WHERE LOWER(domain_name) LIKE ?`,
		"%."+strings.ReplaceAll(strings.ReplaceAll(domaine, "%", `\%`), "_", `\_`))
	if err != nil {
		return fmt.Errorf("lecture des sous-domaines de %s : %w", domaine, err)
	}
	defer rows.Close()
	var enfants []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return err
		}
		if domainname.SousDomaineDe(d, domaine) && d != domaine {
			enfants = append(enfants, d)
		}
	}
	if len(enfants) > 0 {
		return fmt.Errorf(
			"le groupe %s est le dernier du domaine %s, qui a des sous-domaines (%s) : "+
				"le supprimer ferait disparaître %s sous eux. Supprimez d'abord les sous-domaines, "+
				"ou créez un autre groupe dans %s", groupName, domaine, strings.Join(enfants, ", "), domaine, domaine)
	}
	return nil
}
