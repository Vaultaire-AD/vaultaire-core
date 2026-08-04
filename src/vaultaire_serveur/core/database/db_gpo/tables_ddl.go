package dbgpo

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
