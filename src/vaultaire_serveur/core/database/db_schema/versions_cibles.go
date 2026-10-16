package dbschema

import (
	"database/sql"

	"vaultaire/core/database/schematools"
)

// Les versions attendues des agents — TO-DO 111.
//
// Deux colonnes, sur deux tables existantes ; le troisième niveau, le défaut du
// parc, est une ligne de server_settings (clé parcversion.CleReglageParc).
//
//	id_logiciels.agent_target_version   dérogation d'une machine
//	groups.agent_target_version         cible d'un groupe — les anneaux
//
// # Pas dans les CREATE TABLE
//
// Comme les horodatages de l'annuaire : une colonne écrite dans le CREATE n'atteint
// jamais une base en service, et l'écrire aux deux endroits ferait deux
// définitions à tenir d'accord. EnsureColumn pose la colonne sur une base neuve
// comme sur une ancienne.
//
// # Vide par défaut, et c'est la sûreté
//
// Une colonne vide = aucune cible à ce niveau. Une base migrée n'a donc
// aucune cible nulle part, et aucune machine ne se mettra à jour tant que
// personne n'en pose une.
const (
	ColonneVersionCible    = "agent_target_version"
	DefinitionVersionCible = "VARCHAR(64) NOT NULL DEFAULT ''"
)

// EnsureVersionsCibles complète id_logiciels et groups.
//
// # Groupes : la date de modification LDAP ne doit pas bouger
//
// `groups.updated_at` est tenue par la base (ON UPDATE CURRENT_TIMESTAMP) et
// sert de modifyTimestamp à la synchronisation de Keycloak. Poser une cible de
// version sur un groupe n'est pas visible d'un client LDAP : l'écriture
// (dbclients.DefinirCibleGroupe) écrit donc `updated_at = updated_at`, pour ne
// pas faire réimporter le groupe. L'ALTER, lui, ne touche aucune ligne.
func EnsureVersionsCibles(db *sql.DB) error {
	for _, table := range []string{"id_logiciels", "groups"} {
		if err := schematools.EnsureColumn(db, "agent-update", table,
			ColonneVersionCible, DefinitionVersionCible); err != nil {
			return err
		}
	}
	return nil
}
