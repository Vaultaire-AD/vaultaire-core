package dbgroups

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// NomsDesGroupesDeLUtilisateur rend les groupes d'un compte, par leur NOM.
//
// # Pourquoi les noms et non les identifiants
//
// Command_GET_UserGroupIDs existe déjà et rend des entiers, qui servent au
// contrôle des droits. Ce qu'une machine du parc doit poser dans `/etc/group`,
// ce sont des noms : un identifiant de base n'a aucun sens hors du serveur, et
// le traduire côté agent supposerait une seconde requête par groupe.
//
// # L'ordre
//
// Trié par nom, pour que deux lectures successives rendent la même chose. Sans
// tri, l'ordre dépend du plan d'exécution ; la liste envoyée à la machine
// changerait d'un jour à l'autre sans qu'aucune appartenance ait bougé, et les
// journaux des deux côtés se rempliraient de différences qui n'en sont pas.
func NomsDesGroupesDeLUtilisateur(db *sql.DB, username string) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}
	if err := database.SanitizeIdentifier(username); err != nil {
		return nil, err
	}

	userID, trouve, err := database.LookupUserID(db, username)
	if err != nil {
		return nil, fmt.Errorf("recherche de %q : %w", username, err)
	}
	if !trouve {
		// Compte inconnu : aucune erreur, aucune appartenance. L'appelant est
		// déjà passé par l'authentification — un compte qui disparaîtrait entre
		// les deux ne doit pas faire échouer une session en cours d'ouverture.
		return nil, nil
	}

	rows, err := db.Query(`
		SELECT g.group_name
		  FROM users_group ug
		  JOIN groups g ON g.id_group = ug.d_id_group
		 WHERE ug.d_id_user = ?
		 ORDER BY g.group_name`, userID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: groupes de "+username+" illisibles : "+err.Error())
		return nil, fmt.Errorf("lecture des groupes de %q : %w", username, err)
	}
	defer func() { _ = rows.Close() }()

	var noms []string
	for rows.Next() {
		var nom string
		if err := rows.Scan(&nom); err != nil {
			return nil, fmt.Errorf("lecture d'un nom de groupe : %w", err)
		}
		noms = append(noms, nom)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des groupes de %q : %w", username, err)
	}
	return noms, nil
}
