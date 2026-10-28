package dbschema

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database/schematools"
)

// Les jeux de clés de confiance des paquets — TO-DO 207.
//
// pkg_trust_sets : tous les jeux publiés, GARDÉS. Une machine qui demande
// avec le numéro N reçoit le plus petit au-dessus de N : c'est la chaîne qui
// laisse une machine éteinte pendant une rotation la rattraper seule. Un jeu
// ne se modifie ni ne s'efface.
//
// id_logiciels.agent_pkg_trust : le numéro que la machine a déclaré tenir à sa
// dernière demande (09_09) — ce que « vlt agent » et « --pkg-key rotate-status »
// comptent avant de basculer.

// TableJeuxCles est la table des jeux publiés.
const TableJeuxCles = "pkg_trust_sets"

// SchemaJeuxCles : la table.
const SchemaJeuxCles = `CREATE TABLE IF NOT EXISTS ` + TableJeuxCles + ` (
	numero    INT NOT NULL PRIMARY KEY,
	corps     TEXT NOT NULL,
	enveloppe TEXT NOT NULL,
	cree_le   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

// EnsureJeuxDeCles pose la table et la colonne. Fatale au démarrage : la
// demande 09_09, émise par chaque agent à chaque connexion, les nomme.
func EnsureJeuxDeCles(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if _, err := db.Exec(SchemaJeuxCles); err != nil {
		return fmt.Errorf("table %s : %w", TableJeuxCles, err)
	}
	return schematools.EnsureColumn(db, "agent-update", "id_logiciels", "agent_pkg_trust", "INT NOT NULL DEFAULT 0")
}
