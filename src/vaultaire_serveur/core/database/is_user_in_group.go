package database

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// IsUserInGroup vit dans le socle et non dans dbgroups, alors que c'est une
// lecture d'appartenance ordinaire. La raison est une contrainte de
// dépendances : IsSuperadmin en a besoin, et le socle ne peut importer aucun
// sous-paquet — dbgroups importe déjà les gardes ci-dessus, l'inverse formerait
// un cycle. La déplacer demanderait de dupliquer la requête dans le socle, ce
// qui est exactement ce que le §2.2 vient de supprimer.
// IsUserInGroup indique si un utilisateur appartient à un groupe donné.
//
// Utilisé notamment pour la porte d'entrée superadmin des restrictions GPO
// (voir IsSuperadmin, juste en dessous) : l'appartenance est relue en base à
// chaque vérification, jamais mise en cache, pour qu'un retrait du groupe
// prenne effet immédiatement.
func IsUserInGroup(db *sql.DB, username, groupName string) (bool, error) {
	if err := SanitizeIdentifier(username, groupName); err != nil {
		return false, err
	}
	if db == nil {
		return false, fmt.Errorf("connexion base indisponible")
	}
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM users u
		 INNER JOIN users_group ug ON ug.d_id_user = u.id_user
		 INNER JOIN groups g ON g.id_group = ug.d_id_group
		 WHERE u.username = ? AND g.group_name = ?`,
		username, groupName,
	).Scan(&count)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf(
			"appartenance %s/%s : vérification échouée : %v", username, groupName, err))
		return false, err
	}
	return count > 0, nil
}
