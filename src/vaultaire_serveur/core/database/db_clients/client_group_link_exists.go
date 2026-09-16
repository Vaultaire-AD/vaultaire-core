package dbclients

import (
	database "vaultaire/core/database"
)

// clientGroupLinkExists indique si un client est déjà rattaché à un groupe.
//
// Même raison que son homologue côté groupes : logiciel_group appartient à ce
// paquet, seule la mécanique de lecture est empruntée à database.CountLink.
func clientGroupLinkExists(q database.RowQuerier, clientID, groupID int) (bool, error) {
	return database.CountLink(q,
		`SELECT COUNT(*) FROM logiciel_group WHERE d_id_logiciel = ? AND d_id_group = ?`,
		clientID, groupID)
}
