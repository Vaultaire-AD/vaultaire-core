package dbschema

import (
	"database/sql"
	"log"
	"vaultaire/core/logs"
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
			os VARCHAR(255) NOT NULL,

			-- Versions déclarées par le programme lui-même, dans l'inventaire
			-- 02_12. Le core les STOCKE et les AFFICHE ; il ne les interprète
			-- jamais — aucun refus, aucun seuil, aucune comparaison.
			--
			-- Deux colonnes et non une : l'agent et le socle réseau ne bougent
			-- pas ensemble. Une correction du provisionnement des groupes ne
			-- touche pas au protocole, et l'inverse est vrai aussi. Un seul
			-- numéro pour les deux obligerait à monter l'un pour une raison qui
			-- ne le concerne pas.
			--
			-- Vide = jamais déclaré. Un agent d'une version antérieure n'envoie
			-- pas ces lignes ; il apparaît « inconnue » dans les vues, ce qui est
			-- exactement l'information utile pour un déploiement.
			agent_version VARCHAR(64) NOT NULL DEFAULT '',
			sdk_version VARCHAR(64) NOT NULL DEFAULT ''
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

		// ----- GPO -----
		// Le schéma GPO (gpo, gpo_module, gpo_group) est créé par le package
		// dédié core/database/db_gpo, appelé depuis main après cette fonction.
		// Il y remplace l'ancien modèle linux_gpo_distributions / group_linux_gpo,
		// qui stockait une commande shell brute par distribution — donc de
		// l'exécution de code arbitraire en root, sans catalogue ni garde-fou.
		// dbgpo.CreateTables supprime ces deux tables si elles subsistent.

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

		// ----- Clusterisation intelligente -----
		//
		// Les quatre dernières colonnes servent la DÉCOUVERTE DE SERVICE : ce
		// que le core annonce aux agents dans la trame 04_04. Voir
		// « Découverte de service et proxies » dans Protocole_Ducky.md.
		//
		// `capabilities` reste un JSON libre pour ce qu'on affiche sans
		// l'interpréter. Le port, la priorité et l'exposition sont des colonnes
		// parce qu'on TRIE et qu'on FILTRE dessus — les laisser dans le JSON
		// reviendrait à trier en Go ce que la base sait faire, et à découvrir
		// les entrées malformées une par une, à la lecture.
		`CREATE TABLE IF NOT EXISTS cluster_nodes (
    		id_node INT AUTO_INCREMENT PRIMARY KEY,
    		hostname VARCHAR(255) NOT NULL UNIQUE,
    		fqdn VARCHAR(255) NOT NULL UNIQUE,
    		ip_address VARCHAR(45) NOT NULL,
    		role VARCHAR(50) NOT NULL,            -- ex: 'proxy', 'api', 'core', 'dashboard'
    		status VARCHAR(20) DEFAULT 'offline',  -- 'online', 'offline', 'maintenance'
    		version_code VARCHAR(50) NOT NULL,     -- Pour le versionning / hot-patching
    		capabilities JSON,                     -- Pour les spécificités (ex: {"protocol": "https"})
    		last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
    		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    		-- Port d'écoute Ducky. 0 vaut « non déclaré » et non « port zéro » :
    		-- un nœud sans port est OMIS de la liste servie aux agents, plutôt
    		-- que d'y figurer avec une adresse qu'ils composeraient au hasard.
    		ducky_port INT NOT NULL DEFAULT 0,

    		-- Ordonne les nœuds de même rôle. Plus petit = servi plus tôt.
    		-- Zéro vaut « sans préférence » et se range APRÈS les valeurs
    		-- explicites : sinon, donner une priorité à un seul nœud le
    		-- reléguerait derrière tous les autres.
    		priorite INT NOT NULL DEFAULT 0,

    		-- Retire ce nœud de la liste distribuée. VRAI par défaut, et ce
    		-- n'est PAS un contrôle d'accès : le drapeau retire une adresse
    		-- d'une liste, il n'empêche personne de se connecter. Le pare-feu
    		-- reste ce qui protège un core.
    		expose_aux_agents BOOLEAN NOT NULL DEFAULT TRUE,

    		-- Empreinte de la clé publique que CE nœud sert aux agents, écrite
    		-- par lui-même : personne d'autre ne détient sa clé privée, donc
    		-- personne d'autre ne saurait dire si elle correspond.
    		--
    		-- Un nœud sans empreinte est OMIS de la liste. Un agent qui
    		-- apprendrait son adresse sans elle devrait accepter sa clé en
    		-- aveugle — c'est-à-dire faire exactement ce que le fichier
    		-- d'empreintes existe pour empêcher.
    		key_fingerprint VARCHAR(80) NOT NULL DEFAULT '',

    		-- Version du socle réseau lié à ce nœud.
    		--
    		-- La colonne version_code porte déjà la version du programme. Celle-ci
    		-- répond à l'autre question du point 39 : « quel SDK a servi à
    		-- construire cette image ». Vide pour le core, qui n'embarque pas
    		-- le SDK — c'est lui qui juge les clients, il ne partage pas leur
    		-- socle.
    		sdk_version VARCHAR(64) NOT NULL DEFAULT '',

    		-- Le SEUL client autorisé à modifier cette ligne.
    		--
    		-- Sans cette colonne, un nœud déclarait son hostname, son IP et son
    		-- RÔLE dans le CONTENU de la trame 04_01, sans aucun lien avec la
    		-- session authentifiée. Un proxy enrôlé pouvait donc envoyer le
    		-- hostname d'un core existant : l'écriture écrasait sa ligne —
    		-- adresse, port et EMPREINTE comprises — et la liste servie aux
    		-- agents annonçait ensuite l'empreinte de l'attaquant sous le nom du
    		-- core. Les agents l'apprenaient et s'y connectaient pour
    		-- s'authentifier.
    		--
    		-- Deux formes : « <client_software_id> » pour un nœud enregistré par
    		-- le réseau, « @core:<hostname> » pour un core qui se déclare
    		-- lui-même, sans session. Le préfixe « @ » est réservé et refusé à
    		-- tout propriétaire venu d'une session.
    		--
    		-- UNIQUE : un client possède au plus une ligne. Deux lignes pour un
    		-- même propriétaire rendraient « la ligne du demandeur » ambiguë.
    		owner_client_id VARCHAR(191) NOT NULL DEFAULT '',
    		UNIQUE KEY uk_owner (owner_client_id)
		);`,

		// ----- Métriques proxy (exposées pour l'interface Web) -----
		`CREATE TABLE IF NOT EXISTS proxy_metrics (
    		id_metric INT AUTO_INCREMENT PRIMARY KEY,
    		proxy_hostname VARCHAR(255) NOT NULL,
    		proxy_ip VARCHAR(45) NOT NULL,
    		metric_type VARCHAR(64) NOT NULL,       -- 'connections_total', 'requests_ldap', 'requests_ducky', 'backend_errors', etc.
    		metric_value DOUBLE NOT NULL,
    		extra JSON,                             -- données additionnelles (backend_id, core_hostname, etc.)
    		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    		INDEX idx_proxy (proxy_hostname),
    		INDEX idx_created (created_at)
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
			logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: "+"Erreur lors de la création de la table : "+err.Error())
			log.Fatalf("Erreur lors de la création de la table : %v", err)
		}
	}

	// Compléments de schéma sur les tables DÉJÀ créées.
	//
	// `CREATE TABLE IF NOT EXISTS` ne fait rien sur une table existante : elle ne
	// compare pas les colonnes. Une colonne ajoutée au texte ci-dessus n'atteint
	// donc jamais une base en service, et le défaut se manifeste bien plus tard,
	// à la première requête qui la nomme — « Unknown column », en exploitation,
	// sur un chemin qui marchait la veille.
	//
	// Ici plutôt que dans main : c'est le même sujet que ce qui précède, et le
	// séparer laisserait un jour créer les tables sans les compléter.
	if err := EnsureClusterNodesSchema(db); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: complément du schéma cluster_nodes échoué : "+err.Error())
		log.Fatalf("Erreur lors du complément du schéma cluster_nodes : %v", err)
	}

	logs.Write_Log("INFO", "database: all tables and relations created successfully")
}
