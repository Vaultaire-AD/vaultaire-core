package dbgroups

import (
	database "vaultaire/core/database"
)

// userGroupLinkExists indique si un utilisateur est déjà rattaché à un groupe.
//
// La requête vit ici et non dans le socle : users_group est une table de ce
// paquet, et c'est lui qui doit savoir comment on l'interroge. Seule la
// mécanique de lecture est empruntée à database.CountLink.
func userGroupLinkExists(q database.RowQuerier, userID, groupID int) (bool, error) {
	return database.CountLink(q,
		`SELECT COUNT(*) FROM users_group WHERE d_id_user = ? AND d_id_group = ?`,
		userID, groupID)
}
