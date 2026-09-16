package dbldap

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/database"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// GetUsersByUsernames lit plusieurs utilisateurs en UNE requête.
//
// # Pourquoi ça existe
//
// La résolution d'une recherche LDAP appelait GetUserByUsername une fois par
// utilisateur trouvé. Sur un annuaire de 5 000 comptes, une recherche subtree
// produisait 5 000 requêtes SQL — et rien ne bornait le nombre de recherches.
//
// La requête est la même que GetUserByUsername, avec un IN au lieu d'un égal.
// Les paramètres restent liés : ils ne sont jamais concaténés dans le SQL.
//
// Retourne une map indexée par nom d'utilisateur. Un nom absent de la map n'a
// pas été trouvé — ce n'est pas une erreur, l'appelant décide quoi en faire.
func GetUsersByUsernames(db *sql.DB, usernames []string) (map[string]ldapstorage.User, error) {
	résultat := make(map[string]ldapstorage.User, len(usernames))
	if len(usernames) == 0 {
		return résultat, nil
	}

	// Déduplication en amont : la même personne appartient souvent à plusieurs
	// groupes, et la liste reçue porte alors son nom autant de fois.
	uniques := make([]string, 0, len(usernames))
	vus := make(map[string]struct{}, len(usernames))
	for _, u := range usernames {
		if _, déjà := vus[u]; déjà {
			continue
		}
		if err := database.SanitizeIdentifier(u); err != nil {
			return nil, err
		}
		vus[u] = struct{}{}
		uniques = append(uniques, u)
	}

	// Découpage en lots.
	//
	// MariaDB accepte beaucoup de paramètres, mais pas un nombre illimité, et
	// une requête à 10 000 marqueurs est de toute façon lente à préparer. Le lot
	// borne les deux sans changer le résultat.
	const tailleLot = 500
	for début := 0; début < len(uniques); début += tailleLot {
		fin := début + tailleLot
		if fin > len(uniques) {
			fin = len(uniques)
		}
		lot := uniques[début:fin]

		marqueurs := strings.TrimSuffix(strings.Repeat("?,", len(lot)), ",")
		args := make([]any, len(lot))
		for i, u := range lot {
			args[i] = u
		}

		query := `
			SELECT
				u.id_user,
				u.username,
				u.firstname,
				u.lastname,
				u.email,
				u.created_at,
				MIN(dg.domain_name) AS domain_name
			FROM users u
			JOIN users_group ug ON u.id_user = ug.d_id_user
			JOIN groups g ON ug.d_id_group = g.id_group
			JOIN domain_group dg ON dg.d_id_group = g.id_group
			WHERE u.username IN (` + marqueurs + `)
			GROUP BY u.id_user, u.username, u.created_at`

		rows, err := db.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("lecture des utilisateurs : %w", err)
		}
		for rows.Next() {
			var user ldapstorage.User
			if err := rows.Scan(&user.ID, &user.Username, &user.Firstname,
				&user.Lastname, &user.Email, &user.Created_at, &user.GroupDomain); err != nil {
				rows.Close()
				return nil, fmt.Errorf("lecture d'une ligne utilisateur : %w", err)
			}
			résultat[user.Username] = user
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("parcours des utilisateurs : %w", err)
		}
		rows.Close()
	}
	return résultat, nil
}

// GetMemberOfByUsername rend les groupes d'un utilisateur, avec leur domaine.
//
// # Pourquoi ça existe
//
// memberOfForUser lisait TOUS les groupes du domaine, puis interrogeait chacun
// d'eux pour savoir s'il contenait l'utilisateur. Avec 500 groupes, cela faisait
// 501 requêtes pour lire un seul compte — sur le chemin exact qu'emprunte
// JumpServer après chaque authentification.
//
// Une jointure répond à la même question en une requête.
func GetMemberOfByUsername(db *sql.DB, username string) ([]GroupDomain, error) {
	if err := database.SanitizeIdentifier(username); err != nil {
		return nil, err
	}

	query := `
		SELECT g.group_name, dg.domain_name
		FROM users u
		JOIN users_group ug ON u.id_user = ug.d_id_user
		JOIN groups g ON ug.d_id_group = g.id_group
		JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE u.username = ?
		GROUP BY g.group_name, dg.domain_name`

	rows, err := db.Query(query, username)
	if err != nil {
		return nil, fmt.Errorf("lecture des groupes de %s : %w", username, err)
	}
	defer rows.Close()

	var groupes []GroupDomain
	for rows.Next() {
		var g GroupDomain
		if err := rows.Scan(&g.GroupName, &g.DomainName); err != nil {
			return nil, fmt.Errorf("lecture d'une ligne de groupe : %w", err)
		}
		groupes = append(groupes, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des groupes : %w", err)
	}
	return groupes, nil
}

// GroupDomain associe un groupe à son domaine.
type GroupDomain struct {
	GroupName  string
	DomainName string
}
