package dbschema

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database/schematools"
	"vaultaire/core/logs"
)

// Les colonnes d'horodatage de l'annuaire — point 126.
//
// # Pourquoi elles n'existaient pas
//
// `users` portait déjà `created_at` ; `groups` ne portait rien du tout, et
// aucune des deux tables n'avait de date de MODIFICATION. Or c'est sur
// `modifyTimestamp` que s'appuie la synchronisation incrémentale de Keycloak :
// sans elle, seule la synchronisation complète fonctionne, ce qui relit tout
// l'annuaire à chaque passage et bute sur `sizeLimitExceeded` au-delà de dix
// mille entrées.
const (
	ColonneCreeLe    = "created_at"
	ColonneModifieLe = "updated_at"

	// ON UPDATE CURRENT_TIMESTAMP : la base tient la colonne elle-même.
	//
	// C'est ce qui rend la chose fiable. Bump explicite à chaque point
	// d'écriture, il suffisait d'en oublier un pour qu'une date de modification
	// cesse de bouger — et une date qui ne bouge pas est PIRE que pas de date du
	// tout : elle fait croire à une synchronisation qui n'a rien vu.
	//
	// Reste ce que la base ne peut pas voir : un changement d'appartenance touche
	// `users_group`, pas les lignes du compte ni du groupe. Ces deux points-là
	// sont bumpés à la main — voir db_groups/add_user_to_group.go.
	//
	// # Quelles écritures sont exemptées, et lesquelles ne le sont pas
	//
	// La règle : sont exemptées — par `updated_at = updated_at` — les écritures
	// qui ont lieu à CHAQUE authentification. Le réencodage d'une empreinte, le
	// compteur TOTP, la date de dernier changement de mot de passe : rien de cela
	// n'est visible d'un client LDAP, et laisser la date bouger ferait réimporter
	// le compte à chaque connexion.
	//
	// Les écritures RARES — activer un second facteur, le réinitialiser, marquer
	// un mot de passe comme provisoire — bumpent la date, et c'est laissé tel
	// quel. Elles coûtent une relecture d'une entrée, une fois. Sur-synchroniser
	// vaut mieux que manquer un changement, et c'est le sens de tout ce réglage
	// par défaut.
	DefinitionModifieLe = "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
	DefinitionCreeLe    = "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
)

// EnsureHorodatagesAnnuaire complète `users` et `groups` sur une base existante.
//
// # Ce que la migration fait aux lignes déjà là
//
// Elles prennent l'instant de la migration comme date de création et de
// modification. C'est faux pour la création — l'information n'existe nulle part
// pour `groups` — et cela a une conséquence à connaître : au premier passage
// après la mise à jour, tout l'annuaire paraît « modifié à l'instant », donc un
// client incrémental fait une passe complète. UNE fois, puis l'incrémental
// fonctionne. L'inverse — laisser les dates à zéro — ferait paraître l'annuaire
// entier antérieur à tout, et un client ne le resynchroniserait JAMAIS.
//
// L'appelant la traite comme FATALE, et c'est délibéré : les requêtes de lecture
// LDAP nomment ces colonnes. Les rendre facultatives ne rendrait pas leur absence
// inoffensive, elle la déplacerait à la première recherche — « Unknown column »,
// en exploitation, sur un annuaire qui marchait la veille.
func EnsureHorodatagesAnnuaire(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}

	colonnes := []struct {
		table      string
		colonne    string
		definition string
	}{
		// `users.created_at` existe depuis toujours dans le texte de création —
		// mais pas forcément dans une base assez ancienne, et EnsureColumn ne fait
		// rien quand la colonne est là.
		{"users", ColonneCreeLe, DefinitionCreeLe},
		{"users", ColonneModifieLe, DefinitionModifieLe},
		{"groups", ColonneCreeLe, DefinitionCreeLe},
		{"groups", ColonneModifieLe, DefinitionModifieLe},
	}

	for _, c := range colonnes {
		if err := schematools.EnsureColumn(db, "annuaire", c.table, c.colonne, c.definition); err != nil {
			return fmt.Errorf("%s.%s : %w", c.table, c.colonne, err)
		}
	}

	logs.Write_Log("DEBUG", "database: horodatages de l'annuaire en place (users, groups)")
	return nil
}
