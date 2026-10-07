package dbrevocation

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database/schematools"
	"vaultaire/core/logs"
)

// CreateTables crée le schéma de révocation s'il n'existe pas.
func CreateTables(db *sql.DB) error {
	statements := []string{
		// user_revocation : un ordre déclenché par un administrateur.
		//
		// `username` est stocké en TEXTE, sans clé étrangère vers users, et
		// c'est délibéré. En mode hard le compte est supprimé de l'annuaire :
		// une clé étrangère ON DELETE CASCADE effacerait l'ordre au moment même
		// où il devient utile, et le parc n'aurait plus rien à appliquer. La
		// trace doit survivre à son sujet — c'est aussi ce qui permet de
		// répondre à « qui a supprimé ce compte, quand, et pourquoi ? » six
		// mois plus tard.
		//
		// Le verrouillage soft se lit ici (une ligne active, lifted_at nul)
		// plutôt que dans une colonne de `users`, pour la même raison : le mode
		// hard n'aurait nulle part où vivre une fois le compte supprimé.
		`CREATE TABLE IF NOT EXISTS user_revocation (
			id_revocation  INT AUTO_INCREMENT PRIMARY KEY,
			username       VARCHAR(255) NOT NULL,
			mode           VARCHAR(16)  NOT NULL,
			reason_code    VARCHAR(32)  NOT NULL,
			issued_by      VARCHAR(255) NOT NULL,
			issued_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
			lifted_by      VARCHAR(255) NULL,
			lifted_at      DATETIME NULL,
			INDEX idx_revocation_username (username),
			INDEX idx_revocation_active (username, lifted_at)
		);`,

		// user_revocation_target : une ligne par machine visée par un ordre.
		//
		// C'est ce qui rend le rejeu possible : tant qu'une ligne est en
		// « pending » ou « failed », la machine correspondante recevra l'ordre —
		// quand elle le réclame (06_04), et sans attendre si elle est connectée
		// (rejeu du core, TO-DO 49). « acked » et « lifted » sont les deux fins.
		`CREATE TABLE IF NOT EXISTS user_revocation_target (
			d_id_revocation INT NOT NULL,
			computeur_id    VARCHAR(255) NOT NULL,
			status          VARCHAR(16) NOT NULL DEFAULT 'pending',
			last_attempt    DATETIME NULL,
			attempts        INT NOT NULL DEFAULT 0,
			detail          TEXT NULL,
			PRIMARY KEY (d_id_revocation, computeur_id),
			INDEX idx_target_pending (computeur_id, status),
			FOREIGN KEY (d_id_revocation) REFERENCES user_revocation(id_revocation) ON DELETE CASCADE
		);`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"revocation: création de table échouée: "+err.Error())
			return fmt.Errorf("création du schéma de révocation : %w", err)
		}
	}

	// attempts : combien de fois l'ordre a été REMIS à cette machine — TO-DO 49.
	//
	// C'est ce qui espace les rejeux du core : dix secondes après le premier
	// envoi, puis le double à chaque fois. Sans ce compte, il aurait fallu
	// déduire l'espacement de l'âge de l'ordre, et une machine revenue trois
	// jours après aurait attendu cinq minutes son deuxième essai.
	//
	// Le CREATE ci-dessus ne fait rien sur une base où la table existe déjà.
	// Le DEFAULT vaut pour les lignes en place : zéro essai, donc rejouées au
	// premier tour si leur machine est connectée — ce qui est exactement ce
	// qu'on veut d'un ordre resté sans réponse.
	if err := schematools.EnsureColumn(db, "revocation", "user_revocation_target", "attempts",
		"INT NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	logs.Write_Log("INFO", "revocation: schéma vérifié")
	return nil
}
