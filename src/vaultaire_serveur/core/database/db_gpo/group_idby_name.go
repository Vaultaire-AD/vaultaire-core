package dbgpo

import (
	"database/sql"
	dbgroups "vaultaire/core/database/db_groups"
)

// groupIDByName résout l'identifiant d'un groupe depuis son nom.
//
// Simple délégation au helper du paquet parent. Ce paquet avait reconstruit sa
// propre copie de la requête — la onzième du projet — alors que
// dbgroups.GetGroupIDByName répond déjà à la question et que db_gpo importe
// déjà database.
//
// Le raccourci est conservé plutôt que remplacé aux deux points d'appel : il
// garde le paquet lisible, et surtout il donne un seul endroit à corriger si la
// résolution d'un groupe change encore. Le durcissement posé sur le helper
// (sanitisation, message de journal exact) profite désormais à db_gpo sans que
// personne ait eu à y penser — ce qui est précisément l'intérêt de ne pas
// recopier une requête.
func groupIDByName(db *sql.DB, groupName string) (int, error) {
	return dbgroups.GetGroupIDByName(db, groupName)
}
