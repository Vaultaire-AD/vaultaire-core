package dbschema

import (
	"database/sql"
	"fmt"

	"vaultaire/core/logs"
)

// MigrationDetacher est le nom de la migration qui introduit le verbe
// « remove » (Détacher).
const MigrationDetacher = "rbac_verbe_detacher"

// objetsDetachables sont les objets qu'une action « group.remove_* » détache.
// Le groupe n'en fait pas partie : on ne détache pas un groupe d'un groupe.
var objetsDetachables = []string{"user", "client", "permission", "gpo"}

// MigrerCleDetacher recopie, UNE fois, chaque « write:delete:<objet> » en
// « write:remove:<objet> ».
//
// # Pourquoi
//
// Retirer un compte, une machine, une permission ou une GPO d'un groupe
// exigeait la clé « delete » de l'objet. Ces retraits exigent désormais
// « write:remove:<objet> » (Détacher). Sans cette recopie, un délégué qui
// retirait des membres hier ne le pourrait plus aujourd'hui, sans que rien ne
// le lui explique.
//
// La recopie garde la PORTÉE : qui pouvait détacher sur « 1:paris.fr » le peut
// toujours, et nulle part ailleurs. Elle n'ajoute aucun droit qui n'existait pas
// la veille — elle sépare en deux ce qui était confondu.
//
// # Pourquoi une seule fois
//
// Rejouée à chaque démarrage, elle recopierait aussi les permissions créées
// APRÈS la mise à jour : un administrateur qui accorde la suppression sans le
// détachement verrait le second réapparaître au redémarrage. La table
// schema_migrations retient qu'elle a eu lieu.
//
// Après la migration, les deux droits sont indépendants : retirer
// « write:delete:user » à un délégué ne lui retire plus le détachement, et
// inversement. C'est le but.
func MigrerCleDetacher(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if err := creerTableMigrations(db); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("migration %s : %w", MigrationDetacher, err)
	}
	defer func() { _ = tx.Rollback() }()

	// Le verrou de ligne sérialise deux cores qui démarreraient ensemble sur la
	// même base : le second attend, puis voit la migration faite.
	var deja int
	err = tx.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ? FOR UPDATE`,
		MigrationDetacher).Scan(&deja)
	if err != nil {
		return fmt.Errorf("migration %s : lecture : %w", MigrationDetacher, err)
	}
	if deja > 0 {
		return nil
	}

	var total int64
	for _, objet := range objetsDetachables {
		// INSERT IGNORE : une permission qui porterait déjà la nouvelle clé
		// (posée à la main avant le premier démarrage) garde sa valeur.
		res, execErr := tx.Exec(`INSERT IGNORE INTO user_permission_action (id_user_permission, action_key, value)
			SELECT id_user_permission, ?, value FROM user_permission_action WHERE action_key = ?`,
			"write:remove:"+objet, "write:delete:"+objet)
		if execErr != nil {
			return fmt.Errorf("migration %s (%s) : %w", MigrationDetacher, objet, execErr)
		}
		n, _ := res.RowsAffected()
		total += n
	}

	if _, err := tx.Exec(`INSERT INTO schema_migrations (name) VALUES (?)`, MigrationDetacher); err != nil {
		return fmt.Errorf("migration %s : marque : %w", MigrationDetacher, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %s : %w", MigrationDetacher, err)
	}

	logs.Write_Log("INFO", fmt.Sprintf(
		"migration %s : %d droit(s) « write:remove:* » recopié(s) depuis « write:delete:* »",
		MigrationDetacher, total))
	return nil
}

// creerTableMigrations crée la table qui retient les migrations ponctuelles.
func creerTableMigrations(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
			name       VARCHAR(128) PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`); err != nil {
		return fmt.Errorf("création de schema_migrations : %w", err)
	}
	return nil
}
