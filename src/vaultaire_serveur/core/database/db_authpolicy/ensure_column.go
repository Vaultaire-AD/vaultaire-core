package dbauthpolicy

import (
	"database/sql"

	"vaultaire/core/database/schematools"
)

// ensureColumn ajoute une colonne si elle n'existe pas déjà.
//
// # Pourquoi ce n'est plus qu'un renvoi
//
// L'implémentation vivait ici, en privé. Le même besoin est apparu pour
// `cluster_nodes` — une colonne ajoutée au CREATE TABLE n'atteint jamais une
// base existante, puisque `IF NOT EXISTS` ne compare pas les colonnes — et la
// recopier aurait donné deux versions de la même idée.
//
// Deux implémentations d'une règle de schéma finissent toujours par diverger, et
// c'est celle qu'on relit le moins qui se trompe. Elle vit désormais dans
// `core/database/schematools`, avec le motif d'identifiants qui la rend sûre.
//
// La signature locale est conservée : les appelants de ce paquet passent trois
// arguments, et le sujet des journaux — « authpolicy » — est le même pour tous.
func ensureColumn(db *sql.DB, table, column, definition string) error {
	return schematools.EnsureColumn(db, "authpolicy", table, column, definition)
}
