package database

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
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
		`CREATE TABLE IF NOT EXISTS user_permission (
			id_user_permission INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) UNIQUE NOT NULL,
			description TEXT,
			none BOOLEAN NOT NULL DEFAULT FALSE,
			web_admin BOOLEAN NOT NULL DEFAULT FALSE,
			auth BOOLEAN NOT NULL DEFAULT FALSE,
			compare BOOLEAN NOT NULL DEFAULT FALSE,
			search BOOLEAN NOT NULL DEFAULT FALSE,
			can_read BOOLEAN NOT NULL DEFAULT FALSE,
			can_write BOOLEAN NOT NULL DEFAULT FALSE,
			api_read_permission BOOLEAN NOT NULL DEFAULT FALSE,
			api_write_permission BOOLEAN NOT NULL DEFAULT FALSE
		);`,

		// ----- Groupes -----
		`CREATE TABLE IF NOT EXISTS groups (
			id_group INT AUTO_INCREMENT PRIMARY KEY,
			group_name VARCHAR(255) UNIQUE NOT NULL
		);`,

		// Groupes et domaines
		`CREATE TABLE IF NOT EXISTS domain_group (
			id_domain_group INT AUTO_INCREMENT PRIMARY KEY,
			d_id_group INT NOT NULL,
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
		// ----- Données initiales -----
		`INSERT IGNORE INTO users (username, password, salt, date_naissance)
		 VALUES ('vaultaire','5f4dcc3b5aa765d61d8327deb882cf99','abc123salt','1990-01-01');`,
	}

	for _, query := range createTablesSQL {
		_, err := db.Exec(query)
		if err != nil {
			logs.WriteLog("db", "Erreur lors de la création de la table : "+err.Error())
			log.Fatalf("Erreur lors de la création de la table : %v", err)
		}
	}

	fmt.Println("Toutes les tables et relations ont été créées avec succès.")
}
