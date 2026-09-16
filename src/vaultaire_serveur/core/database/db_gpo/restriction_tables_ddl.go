package dbgpo

var restrictionTablesDDL = []string{
	`CREATE TABLE IF NOT EXISTS gpo_restriction (
		id_gpo_restriction INT AUTO_INCREMENT PRIMARY KEY,
		kind VARCHAR(24) NOT NULL,
		module_type VARCHAR(64) NOT NULL DEFAULT '',
		field_name VARCHAR(64) NOT NULL DEFAULT '',
		scope VARCHAR(16) NOT NULL DEFAULT 'any',
		value VARCHAR(512) NOT NULL,
		note VARCHAR(255) DEFAULT NULL,
		updated_by VARCHAR(255) DEFAULT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		UNIQUE KEY uk_gpo_restriction (kind, module_type, field_name, scope, value(191)),
		INDEX idx_gpo_restriction_kind (kind),
		INDEX idx_gpo_restriction_field (module_type, field_name)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

	// Valeurs nommées porteuses d'un contenu (ex. jeux de commandes sudo).
	// Table distincte de gpo_restriction : le contenu peut être long et
	// multiligne, ce qui ne tient pas dans une colonne indexée.
	`CREATE TABLE IF NOT EXISTS gpo_value_definition (
		id_gpo_value_definition INT AUTO_INCREMENT PRIMARY KEY,
		module_type VARCHAR(64) NOT NULL,
		field_name VARCHAR(64) NOT NULL,
		name VARCHAR(128) NOT NULL,
		payload_kind VARCHAR(32) NOT NULL,
		payload TEXT NOT NULL,
		note VARCHAR(255) DEFAULT NULL,
		updated_by VARCHAR(255) DEFAULT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		UNIQUE KEY uk_gpo_value_definition (module_type, field_name, name),
		INDEX idx_gpo_value_definition_field (module_type, field_name)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

	`CREATE TABLE IF NOT EXISTS gpo_field_rule (
		id_gpo_field_rule INT AUTO_INCREMENT PRIMARY KEY,
		module_type VARCHAR(64) NOT NULL,
		field_name VARCHAR(64) NOT NULL,
		mode VARCHAR(16) NOT NULL DEFAULT 'list',
		allow_pattern VARCHAR(512) DEFAULT NULL,
		deny_pattern VARCHAR(512) DEFAULT NULL,
		note VARCHAR(512) DEFAULT NULL,
		updated_by VARCHAR(255) DEFAULT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		UNIQUE KEY uk_gpo_field_rule (module_type, field_name)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,
}
