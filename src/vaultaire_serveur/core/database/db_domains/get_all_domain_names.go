package dbdomains

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// GetAllDomainNames rend les noms de domaine distincts de l'annuaire.
//
// # Pourquoi une requête dédiée
//
// Le chemin LDAP a besoin de savoir si un domaine est servi, et de rien d'autre.
// La seule fonction qui le permettait — `GetAllGroupDomains` — passe par
// `GetAllGroupsWithDomains`, une jointure SANS clause de restriction qui
// matérialise TOUS les groupes du parc pour n'en garder que la colonne du
// domaine.
//
// C'était acceptable là où elle était déjà appelée. Ce ne l'est plus sur le
// contrôle d'existence d'une recherche, qui s'exécute à CHAQUE requête — y
// compris sur la relecture en scope `base` que JumpServer et django-auth-ldap
// font après chaque authentification, laquelle ne lisait jusqu'ici aucune ligne
// de la table des groupes.
//
// `SELECT DISTINCT domain_name` lit une colonne d'une table, et la base fait le
// dédoublonnage.
func GetAllDomainNames(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT DISTINCT domain_name FROM domain_group WHERE domain_name <> ''`)
	if err != nil {
		return nil, fmt.Errorf("lecture des domaines : %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.Write_Log("ERROR", "db_domains: fermeture du curseur : "+err.Error())
		}
	}()

	var domaines []string
	for rows.Next() {
		var nom string
		if err := rows.Scan(&nom); err != nil {
			return nil, fmt.Errorf("lecture d'un domaine : %w", err)
		}
		domaines = append(domaines, nom)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des domaines : %w", err)
	}
	return domaines, nil
}
