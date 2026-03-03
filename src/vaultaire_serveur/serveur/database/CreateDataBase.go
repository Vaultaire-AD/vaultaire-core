package database

import (
	"vaultaire/serveur/logs"
	"database/sql"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

func Create_DataBase(db *sql.DB) {
	createTablesSQL := []string{
		// ----- Utilisateurs -----
		`CREATE TABLE IF NOT EXISTS users (
			id_user INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			firstname VARCHAR(255) NOT NULL,
			lastname VARCHAR(255) NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			salt VARCHAR(255) NOT NULL,
			date_naissance DATE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			
		);`,

		// ----- Permissions CLIENT (anciennement "permission") -----
		`CREATE TABLE IF NOT EXISTS client_permission (
			id_permission INT AUTO_INCREMENT PRIMARY KEY,
			name_permission VARCHAR(255) UNIQUE NOT NULL,
			is_admin BOOLEAN NOT NULL DEFAULT FALSE
		);`,

		// ----- Permissions Utilisateur (type LDAP) -----
		// RBAC: none, web_admin, auth, compare, search restent en colonnes; lecture/écriture par objet dans user_permission_action
		`CREATE TABLE IF NOT EXISTS user_permission (
   			id_user_permission INT AUTO_INCREMENT PRIMARY KEY,
    		name VARCHAR(255) UNIQUE NOT NULL,
    		description TEXT,
    		none TEXT DEFAULT 'nil',
    		web_admin TEXT DEFAULT 'nil',
    		auth TEXT DEFAULT 'nil',
    		compare TEXT DEFAULT 'nil',
    		search TEXT DEFAULT 'nil'
		);`,

		// Actions granulaires format catégorie:action:objet (ex: read:get:user, write:create:group)
		`CREATE TABLE IF NOT EXISTS user_permission_action (
			id_user_permission INT NOT NULL,
			action_key VARCHAR(128) NOT NULL,
			value TEXT DEFAULT 'nil',
			PRIMARY KEY (id_user_permission, action_key),
			FOREIGN KEY (id_user_permission) REFERENCES user_permission(id_user_permission) ON DELETE CASCADE
		);`,

		// ----- Groupes -----
		`CREATE TABLE IF NOT EXISTS groups (
			id_group INT AUTO_INCREMENT PRIMARY KEY,
			group_name VARCHAR(255) UNIQUE NOT NULL
		);`,

		// Groupes et domaines
		`CREATE TABLE IF NOT EXISTS domain_group (
			id_domain_group INT AUTO_INCREMENT PRIMARY KEY,
			d_id_group INT NOT NULL UNIQUE,
			domain_name VARCHAR(255) NOT NULL,
			FOREIGN KEY (d_id_group) REFERENCES groups(id_group) ON DELETE CASCADE
		);`,

		// Association utilisateurs ↔ groupes
		`CREATE TABLE IF NOT EXISTS users_group (
			d_id_user INT NOT NULL,
			d_id_group INT NOT NULL,
			PRIMARY KEY (d_id_user, d_id_group),
			FOREIGN KEY (d_id_user) REFERENCES users(id_user) ON DELETE CASCADE,
			FOREIGN KEY (d_id_group) REFERENCES groups(id_group) ON DELETE CASCADE
		);`,

		// Association groupes ↔ permissions UTILISATEUR (LDAP)
		`CREATE TABLE IF NOT EXISTS group_user_permission (
			d_id_group INT NOT NULL,
			d_id_user_permission INT NOT NULL,
			PRIMARY KEY (d_id_group, d_id_user_permission),
			FOREIGN KEY (d_id_group) REFERENCES groups(id_group) ON DELETE CASCADE,
			FOREIGN KEY (d_id_user_permission) REFERENCES user_permission(id_user_permission) ON DELETE CASCADE
		);`,

		// Groupe ↔ permission CLIENT spécifique à un logiciel
		`CREATE TABLE IF NOT EXISTS group_permission_logiciel (
			d_id_group INT NOT NULL,
			d_id_permission INT NOT NULL,
			PRIMARY KEY (d_id_group, d_id_permission),
			FOREIGN KEY (d_id_group) REFERENCES groups(id_group) ON DELETE CASCADE,
			FOREIGN KEY (d_id_permission) REFERENCES client_permission(id_permission) ON DELETE CASCADE
		);`,

		// ----- Logiciels -----
		`CREATE TABLE IF NOT EXISTS id_logiciels (
			id_logiciel INT AUTO_INCREMENT PRIMARY KEY,
			public_key TEXT NOT NULL,
			logiciel_type VARCHAR(255) NOT NULL,
			computeur_id VARCHAR(255) NOT NULL,
			hostname VARCHAR(255) NOT NULL,
			serveur BOOLEAN NOT NULL DEFAULT FALSE,
			processeur INT NOT NULL,
			ram VARCHAR(255) NOT NULL,
			os VARCHAR(255) NOT NULL
		);`,

		// Logiciels ↔ groupes
		`CREATE TABLE IF NOT EXISTS logiciel_group (
			d_id_logiciel INT NOT NULL,
			d_id_group INT NOT NULL,
			PRIMARY KEY (d_id_logiciel, d_id_group),
			FOREIGN KEY (d_id_logiciel) REFERENCES id_logiciels(id_logiciel) ON DELETE CASCADE,
			FOREIGN KEY (d_id_group) REFERENCES groups(id_group) ON DELETE CASCADE
		);`,

		// Connexions utilisateur ↔ logiciel (sessions actives)
		`CREATE TABLE IF NOT EXISTS did_login (
			id_login INT AUTO_INCREMENT PRIMARY KEY,
			d_id_user INT NOT NULL,
			session_key BLOB NOT NULL,
			key_time_validity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			d_id_logiciel INT NOT NULL,
			FOREIGN KEY (d_id_user) REFERENCES users(id_user) ON DELETE CASCADE,
			FOREIGN KEY (d_id_logiciel) REFERENCES id_logiciels(id_logiciel) ON DELETE CASCADE
		);`,

		// Sessions logicielles
		`CREATE TABLE IF NOT EXISTS sessions (
			id INT AUTO_INCREMENT PRIMARY KEY,
			ordinateur_id_d INT NOT NULL,
			session_nom VARCHAR(255) NOT NULL,
			FOREIGN KEY (ordinateur_id_d) REFERENCES id_logiciels(id_logiciel) ON DELETE CASCADE
		);`,

		// Historique des logiciels utilisés par utilisateur
		`CREATE TABLE IF NOT EXISTS users_logiciel (
			d_id_user INT NOT NULL,
			d_id_logiciel INT NOT NULL,
			recent_utilisation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (d_id_user, d_id_logiciel),
			FOREIGN KEY (d_id_user) REFERENCES users(id_user) ON DELETE CASCADE,
			FOREIGN KEY (d_id_logiciel) REFERENCES id_logiciels(id_logiciel) ON DELETE CASCADE
		);`,

		// ----- GPO Linux par distribution -----
		`CREATE TABLE IF NOT EXISTS linux_gpo_distributions (
			id INT AUTO_INCREMENT PRIMARY KEY,
			gpo_name VARCHAR(255) NOT NULL,
			ubuntu TEXT,
			debian TEXT,
			rocky TEXT
		);`,

		// Groupes ↔ GPO
		`CREATE TABLE IF NOT EXISTS group_linux_gpo (
			d_id_group INT NOT NULL,
			d_id_gpo INT NOT NULL,
			PRIMARY KEY (d_id_group, d_id_gpo),
			FOREIGN KEY (d_id_group) REFERENCES groups(id_group) ON DELETE CASCADE,
			FOREIGN KEY (d_id_gpo) REFERENCES linux_gpo_distributions(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS user_public_keys (
    		id_key INT AUTO_INCREMENT PRIMARY KEY,
    		id_user INT NOT NULL,
    		public_key TEXT NOT NULL,
    		label VARCHAR(100) DEFAULT NULL, -- optionnel : nom de la clé pour l'utilisateur
    		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    		CONSTRAINT fk_user FOREIGN KEY (id_user) REFERENCES users(id_user) ON DELETE CASCADE,
    		UNIQUE KEY unique_pubkey (public_key(255))
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

		// ----- Certificats et clés système -----
		`CREATE TABLE IF NOT EXISTS certificates (
    		id_certificate INT AUTO_INCREMENT PRIMARY KEY,
    		name VARCHAR(255) NOT NULL UNIQUE,
    		certificate_type VARCHAR(100) NOT NULL, -- 'rsa_keypair', 'tls_cert', 'ssh_key', etc.
    		certificate_data LONGTEXT, -- Certificat X.509 (PEM) ou certificat SSH
    		private_key_data LONGTEXT, -- Clé privée (PEM)
    		public_key_data LONGTEXT, -- Clé publique (PEM)
    		description TEXT,
    		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    		INDEX idx_name (name),
    		INDEX idx_type (certificate_type)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

		// ----- Données initiales -----
		`INSERT IGNORE INTO users (username, firstname, lastname, email, password, salt, date_naissance)
 			VALUES ('vaultaire','Vault','Admin','vaultaire@example.com','5f4dcc3b5aa765d61d8327deb882cf99','abc123salt','1990-01-01');`,

		`INSERT IGNORE INTO groups (group_name) VALUES ('vaultaire');`,

		// <-- ajout : associer un domaine au groupe "vaultaire"
		`INSERT IGNORE INTO domain_group (d_id_group, domain_name)
			SELECT g.id_group, 'vaultaire.fr'
 			FROM groups g
 			WHERE g.group_name='vaultaire';`,

		`INSERT IGNORE INTO client_permission (name_permission, is_admin)
 			VALUES ('vaultaire_admin', TRUE);`,

		`INSERT IGNORE INTO group_permission_logiciel (d_id_group, d_id_permission)
 			SELECT g.id_group, p.id_permission
 			FROM groups g, client_permission p
 			WHERE g.group_name='vaultaire' AND p.name_permission='vaultaire_admin';`,

		`INSERT IGNORE INTO user_permission (name, description, none, web_admin, auth, compare, search)
			VALUES ('vaultaire_all', 'Permissions complètes pour le groupe vaultaire','all','all','all','all','all');`,

		`INSERT IGNORE INTO user_permission_action (id_user_permission, action_key, value)
			SELECT u.id_user_permission, v.k, 'all' FROM user_permission u
			CROSS JOIN (SELECT 'read:get:user' AS k UNION ALL SELECT 'read:status:user' UNION ALL SELECT 'write:create:user' UNION ALL SELECT 'write:delete:user' UNION ALL SELECT 'write:update:user' UNION ALL SELECT 'write:add:user'
				UNION ALL SELECT 'read:get:group' UNION ALL SELECT 'read:status:group' UNION ALL SELECT 'write:create:group' UNION ALL SELECT 'write:delete:group' UNION ALL SELECT 'write:update:group' UNION ALL SELECT 'write:add:group'
				UNION ALL SELECT 'read:get:client' UNION ALL SELECT 'read:status:client' UNION ALL SELECT 'write:create:client' UNION ALL SELECT 'write:delete:client' UNION ALL SELECT 'write:update:client' UNION ALL SELECT 'write:add:client'
				UNION ALL SELECT 'read:get:permission' UNION ALL SELECT 'read:status:permission' UNION ALL SELECT 'write:create:permission' UNION ALL SELECT 'write:delete:permission' UNION ALL SELECT 'write:update:permission' UNION ALL SELECT 'write:add:permission'
				UNION ALL SELECT 'read:get:gpo' UNION ALL SELECT 'read:status:gpo' UNION ALL SELECT 'write:create:gpo' UNION ALL SELECT 'write:delete:gpo' UNION ALL SELECT 'write:update:gpo' UNION ALL SELECT 'write:add:gpo'
				UNION ALL SELECT 'write:dns' UNION ALL SELECT 'write:eyes') v
			WHERE u.name='vaultaire_all';`,

		`INSERT IGNORE INTO group_user_permission (d_id_group, d_id_user_permission)
			SELECT g.id_group, u.id_user_permission
 			FROM groups g, user_permission u
 			WHERE g.group_name='vaultaire' AND u.name='vaultaire_all';`,

		`INSERT IGNORE INTO users_group (d_id_user, d_id_group)
			SELECT u.id_user, g.id_group
			FROM users u, groups g
			WHERE u.username='vaultaire' AND g.group_name='vaultaire';
		`,
	}

	for _, query := range createTablesSQL {
		_, err := db.Exec(query)
		if err != nil {
			logs.WriteLog("db", "Erreur lors de la création de la table : "+err.Error())
			log.Fatalf("Erreur lors de la création de la table : %v", err)
		}
	}

	logs.Write_Log("INFO", "database: all tables and relations created successfully")
}
