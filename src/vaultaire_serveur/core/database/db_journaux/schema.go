package dbjournaux

import (
	"database/sql"
	"fmt"

	"vaultaire/core/logs"
)

// Table est le nom de la table du journal commun.
const Table = "server_logs"

// Tailles des colonnes, reprises par la troncature à l'insertion.
//
// Une valeur trop longue ferait échouer l'INSERT entier en mode SQL strict — et
// avec lui tout le lot, soit deux cents lignes perdues pour un code d'erreur
// trop bavard. On tronque donc avant.
const (
	tailleNiveau  = 16
	tailleCode    = 32
	tailleCore    = 255
	tailleMeta    = 64
	tailleMessage = 8192 // octets : TEXT se mesure en octets, pas en caractères
)

// ddl est le schéma de la table.
//
// # Les index
//
// Chacun sert un filtre du portail et de `vlt logs`, TOUJOURS combiné à une
// période — c'est la question qu'on pose : « les erreurs de core-2 depuis ce
// matin ». La date vient donc en second dans les index composés.
//
// `created_at` seul sert la purge, qui ne filtre que sur lui.
//
// # Pas de clé étrangère vers cluster_nodes
//
// `core_name` est du TEXTE, comme `username` dans user_revocation : un core
// retiré du cluster doit laisser ses journaux derrière lui. C'est même souvent
// pour comprendre pourquoi il est tombé qu'on les relit.
//
// DATETIME(6) : à la seconde près, deux lignes émises dans la même seconde par
// deux cores ne se départagent pas, et l'ordre de lecture d'un incident en
// dépend.
var ddl = `CREATE TABLE IF NOT EXISTS ` + Table + ` (
	id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
	created_at DATETIME(6)      NOT NULL,
	severity   TINYINT UNSIGNED NOT NULL,
	level      VARCHAR(16)      NOT NULL,
	code       VARCHAR(32)      NOT NULL DEFAULT '',
	core_name  VARCHAR(255)     NOT NULL,
	message    TEXT             NOT NULL,
	request_id VARCHAR(64)      NOT NULL DEFAULT '',
	user_id    VARCHAR(64)      NOT NULL DEFAULT '',
	INDEX idx_server_logs_created  (created_at),
	INDEX idx_server_logs_core     (core_name, created_at),
	INDEX idx_server_logs_severity (severity, created_at),
	INDEX idx_server_logs_code     (code, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`

// CreateTables crée la table du journal commun si elle n'existe pas.
//
// Table NEUVE : `CREATE TABLE IF NOT EXISTS` suffit ici, puisqu'aucune base en
// service ne la porte déjà. Une colonne ajoutée PLUS TARD, elle, devra passer
// aussi par schematools.EnsureColumn — voir « how it work/README.md » § 6.3.
func CreateTables(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("journal commun : connexion base indisponible")
	}
	if _, err := db.Exec(ddl); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBCreateTable,
			"journaux: création de la table "+Table+" échouée : "+err.Error())
		return fmt.Errorf("création de la table %s : %w", Table, err)
	}
	logs.Write_Log("INFO", "journaux: schéma vérifié")
	return nil
}
