// Package dbgpo est la couche de persistance dédiée aux GPO Vaultaire.
//
// Elle est volontairement séparée du package database : les GPO ont leur propre
// schéma (une GPO, N modules, M groupes) et leur propre invariant de sécurité
// (aucun module ne doit entrer en base sans avoir été validé par le catalogue
// core/gpo). Isoler ce code évite que du CRUD générique contourne cette
// validation par inadvertance.
//
// Modèle relationnel :
//
//	gpo         — métadonnées d'une GPO (nom, scope, version, activation)
//	gpo_module  — une ligne par module, paramètres en JSON
//	gpo_group   — liaison N-N vers les groupes (une GPO ne s'applique qu'à des groupes)
package dbgpo

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// tablesDDL contient la définition des tables GPO.
//
// Les paramètres de module sont en JSON plutôt qu'éclatés en colonnes parce que
// chaque type de module a ses propres champs ; le typage réel est porté par le
// schéma déclaratif de core/gpo, qui est la source de vérité. En revanche les
// modules eux-mêmes sont des lignes distinctes, ce qui permet de répondre à
// « quelles GPO touchent sshd ? » et de diffuser un diff module par module.
var tablesDDL = []string{
	`CREATE TABLE IF NOT EXISTS gpo (
		id_gpo INT AUTO_INCREMENT PRIMARY KEY,
		gpo_name VARCHAR(64) NOT NULL UNIQUE,
		scope VARCHAR(16) NOT NULL,
		description TEXT,
		version INT NOT NULL DEFAULT 1,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		INDEX idx_gpo_scope (scope),
		INDEX idx_gpo_enabled (enabled)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

	`CREATE TABLE IF NOT EXISTS gpo_module (
		id_gpo_module INT AUTO_INCREMENT PRIMARY KEY,
		d_id_gpo INT NOT NULL,
		module_type VARCHAR(64) NOT NULL,
		module_scope VARCHAR(16) NOT NULL,
		apply_order INT NOT NULL DEFAULT 100,
		params TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		FOREIGN KEY (d_id_gpo) REFERENCES gpo(id_gpo) ON DELETE CASCADE,
		INDEX idx_gpo_module_type (module_type),
		INDEX idx_gpo_module_order (d_id_gpo, apply_order)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

	`CREATE TABLE IF NOT EXISTS gpo_group (
		d_id_gpo INT NOT NULL,
		d_id_group INT NOT NULL,
		PRIMARY KEY (d_id_gpo, d_id_group),
		FOREIGN KEY (d_id_gpo) REFERENCES gpo(id_gpo) ON DELETE CASCADE,
		FOREIGN KEY (d_id_group) REFERENCES groups(id_group) ON DELETE CASCADE
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,
}

// legacyTablesToDrop liste les tables de l'ancien modèle GPO (une commande shell
// par distribution) supprimées lors du passage au modèle déclaratif. Elles sont
// retirées dans l'ordre des dépendances : la table de liaison d'abord.
var legacyTablesToDrop = []string{
	"group_linux_gpo",
	"linux_gpo_distributions",
}

// CreateTables crée le schéma GPO et supprime les tables de l'ancien modèle.
//
// Appelée depuis main, après database.Create_DataBase : la table gpo_group
// référence groups(id_group), qui doit donc déjà exister.
func CreateTables(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("gpo: connexion base nulle")
	}

	for _, ddl := range tablesDDL {
		if _, err := db.Exec(ddl); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: création du schéma échouée : "+err.Error())
			return fmt.Errorf("gpo: création du schéma échouée : %v", err)
		}
	}

	if err := DropLegacyTables(db); err != nil {
		return err
	}

	logs.Write_Log("INFO", "gpo: schéma déclaratif prêt (gpo, gpo_module, gpo_group)")
	return nil
}

// DropLegacyTables supprime les tables de l'ancien modèle GPO si elles sont
// encore présentes. Idempotent : sans effet sur une base déjà migrée.
func DropLegacyTables(db *sql.DB) error {
	for _, table := range legacyTablesToDrop {
		if _, err := db.Exec("DROP TABLE IF EXISTS " + table); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBGeneric, "gpo: suppression de la table héritée "+table+" échouée : "+err.Error())
			return fmt.Errorf("gpo: suppression de la table héritée %s échouée : %v", table, err)
		}
	}
	return nil
}
