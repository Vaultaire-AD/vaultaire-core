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
	for _, c := range append(append(colonnesCompteRendu, colonnesConfiguration...), colonneRetrogradation...) {
		if err := schematools.EnsureColumn(db, "agent-update", "id_logiciels", c.nom, c.definition); err != nil {
			return err
		}
	}
	return nil
}

// colonnesCompteRendu : le dernier compte rendu 09_04 d'une machine (TO-DO 115).
//
// C'est lui qui distingue « pas encore tenté » de « tenté et revenu en
// arrière » — et qui empêche le core de redonner sans fin le même ordre à une
// machine qui vient d'y échouer : tant que le compte rendu de CETTE version
// est un échec, la demande 09_01 répond « rien à faire », jusqu'à ce qu'un
// « vlt agent update » l'efface.
//
// Une seule ligne par machine, pas d'historique : le journal commun porte le
// détail, et la vue n'a besoin que du dernier mot.
// colonnesConfiguration : le dernier compte rendu 09_07 — la configuration
// système de la machine face à sa version (TO-DO 117). Même règle : une ligne,
// le dernier mot.
// colonneRetrogradation : la dérogation d'une machine peut porter le drapeau
// « --downgrade » (TO-DO 204) ; il s'efface quand la machine rend « installe »
// pour cette version.
var colonneRetrogradation = []struct{ nom, definition string }{
	{"agent_target_downgrade", "TINYINT(1) NOT NULL DEFAULT 0"},
}

var colonnesConfiguration = []struct{ nom, definition string }{
	{"agent_conf_state", "VARCHAR(32) NOT NULL DEFAULT ''"},
	{"agent_conf_reason", "VARCHAR(255) NOT NULL DEFAULT ''"},
	{"agent_conf_at", "DATETIME NULL DEFAULT NULL"},
}

var colonnesCompteRendu = []struct{ nom, definition string }{
	{"agent_update_version", "VARCHAR(64) NOT NULL DEFAULT ''"},
	{"agent_update_result", "VARCHAR(32) NOT NULL DEFAULT ''"},
	{"agent_update_reason", "VARCHAR(255) NOT NULL DEFAULT ''"},
	{"agent_update_at", "DATETIME NULL DEFAULT NULL"},
}
