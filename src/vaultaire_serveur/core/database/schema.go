package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"
	"vaultaire/core/logs"
	"vaultaire/core/storage"

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
		`CREATE TABLE IF NOT EXISTS cluster_nodes (
    		id_node INT AUTO_INCREMENT PRIMARY KEY,
    		hostname VARCHAR(255) NOT NULL UNIQUE,
    		fqdn VARCHAR(255) NOT NULL UNIQUE,
    		ip_address VARCHAR(45) NOT NULL,
    		role VARCHAR(50) NOT NULL,            -- ex: 'proxy', 'api', 'core', 'dashboard'
    		status VARCHAR(20) DEFAULT 'offline',  -- 'online', 'offline', 'maintenance'
    		version_code VARCHAR(50) NOT NULL,     -- Pour le versionning / hot-patching
    		capabilities JSON,                     -- Pour les spécificités (ex: {"port": 8080, "protocol": "https"})
    		last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
    		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
			logs.WriteLog("db", "Erreur lors de la création de la table : "+err.Error())
			log.Fatalf("Erreur lors de la création de la table : %v", err)
		}
	}

	logs.Write_Log("INFO", "database: all tables and relations created successfully")
}

// CreateDefaultAdminUser crée l'utilisateur administrateur par défaut s'il n'existe pas, et l'ajoute au groupe vaultaire.
// Si l'admin existe déjà (ex: redémarrage du conteneur), la création est ignorée et le processus continue.
func CreateDefaultAdminUser(db *sql.DB) {
	logs.Write_Log("INFO", "bootstrap: checking default administrator")

	if storage.Administrateur_Username == "" {
		logs.Write_LogCode("CRITICAL", logs.CodeInternal, "bootstrap: administrator username is empty")
		log.Fatal("bootstrap: administrator username is empty")
	}
	if storage.Administrateur_Password == "" {
		logs.Write_LogCode("CRITICAL", logs.CodeInternal, "bootstrap: administrator password is empty")
		log.Fatal("bootstrap: administrator password is empty")
	}

	userID, err := Get_User_ID_By_Username(db, storage.Administrateur_Username)
	if err == nil {
		logs.Write_Log("INFO", fmt.Sprintf("bootstrap: administrator '%s' already exists (id=%d)", storage.Administrateur_Username, userID))
		_, _ = db.Exec(`
			INSERT IGNORE INTO users_group (d_id_user, d_id_group)
			SELECT ?, g.id_group FROM groups g WHERE g.group_name = 'vaultaire'
		`, userID)
		logs.Write_Log("INFO", "bootstrap: starting with existing administrator")
		return
	}

	logs.Write_Log("INFO", "bootstrap: creating new administrator")
	salt, err := generateSalt(16)
	if err != nil {
		logs.WriteLog("db", "génération salt admin: "+err.Error())
		log.Fatalf("[BOOTSTRAP] Erreur génération salt: %v", err)
	}
	saltHex := hex.EncodeToString(salt)
	saltedPassword := append(salt, []byte(storage.Administrateur_Password)...)
	hash := sha256.Sum256(saltedPassword)
	hashHex := hex.EncodeToString(hash[:])

	firstname := "Admin"
	lastname := "System"
	email := storage.Administrateur_Username + "@vaultaire.local"
	birthdate := "01/01/3300"

	err = Create_New_User(
		GetDatabase(),
		storage.Administrateur_Username,
		firstname,
		lastname,
		email,
		hashHex,
		saltHex,
		birthdate,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeDBQuery, "bootstrap: administrator creation failed: "+err.Error())
		log.Fatalf("bootstrap: administrator creation failed: %v", err)
	}
	logs.Write_Log("INFO", "bootstrap: administrator user created")

	userID, err = Get_User_ID_By_Username(db, storage.Administrateur_Username)
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeDBQuery, "bootstrap: failed to retrieve administrator ID: "+err.Error())
		log.Fatalf("bootstrap: failed to retrieve administrator ID: %v", err)
	}

	// 6. Ajouter la clé publique si fournie
	if storage.Administrateur_PublicKey != "" {
		_, err = db.Exec(`
			INSERT IGNORE INTO user_public_keys (id_user, public_key, label)
			VALUES (?, ?, 'Admin Key')
		`,
			userID,
			storage.Administrateur_PublicKey,
		)
		if err != nil {
			logs.Write_LogCode("WARNING", logs.CodeDBQuery, "bootstrap: failed to add public key: "+err.Error())
		} else {
			logs.Write_Log("INFO", "bootstrap: public key added")
		}
	}

	_, err = db.Exec(`
		INSERT IGNORE INTO users_group (d_id_user, d_id_group)
		SELECT ?, g.id_group
		FROM groups g
		WHERE g.group_name = 'vaultaire'
	`,
		userID,
	)
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeDBQuery, "bootstrap: failed to add administrator to vaultaire group: "+err.Error())
		log.Fatalf("bootstrap: failed to add administrator to vaultaire group: %v", err)
	}

	logs.Write_Log("INFO", fmt.Sprintf("bootstrap: administrator '%s' created and added to vaultaire group", storage.Administrateur_Username))
}

// EnsureSuperadminActions accorde toutes les actions connues à la permission
// d'amorçage `vaultaire_all`.
//
// POURQUOI CETTE FONCTION EXISTE. Create_DataBase énumérait les clés d'action à
// la main, dans une longue clause SQL `UNION ALL`. Cette liste a dérivé du code
// dès le premier ajout : `write:killswitch` n'y figurait pas, donc le groupe
// superadmin lui-même n'avait pas le droit de déclencher le kill switch — et
// comme l'interface masque ce qu'on n'a pas le droit de faire, le bouton
// n'apparaissait nulle part. Le symptôme était une fonctionnalité invisible,
// la cause une liste recopiée.
//
// La liste est désormais fournie par l'appelant depuis
// permission.AllActionKeys(), la seule source de vérité. Elle est passée en
// paramètre plutôt qu'importée : core/permission importe core/database, un
// import dans l'autre sens créerait un cycle. C'est main, qui voit les deux
// paquets, qui fait la liaison.
//
// Appelée à CHAQUE démarrage, avec des INSERT IGNORE : les bases existantes
// reçoivent ainsi les clés apparues depuis leur création, sans script de
// migration. Une clé déjà présente n'est pas écrasée — si un administrateur a
// délibérément restreint une action, on ne la lui rouvre pas dans son dos.
func EnsureSuperadminActions(db *sql.DB, actionKeys []string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if len(actionKeys) == 0 {
		return fmt.Errorf("aucune action à accorder")
	}

	permID, found, err := LookupUserPermissionID(db, ProtectedUserPermission)
	if err != nil {
		return fmt.Errorf("lecture de la permission %s : %w", ProtectedUserPermission, err)
	}
	if !found {
		// La permission n'existe pas encore : Create_DataBase ne l'a pas créée,
		// ce qui arrive sur une base vide au tout premier démarrage si l'ordre
		// des instructions change. Ce n'est pas une erreur bloquante, le
		// prochain démarrage rattrapera.
		logs.Write_Log("WARNING",
			"bootstrap: permission "+ProtectedUserPermission+" absente, actions non accordées")
		return nil
	}

	// Les actions legacy vivent dans des colonnes de user_permission, pas dans
	// la table des actions. Command_SET_UserPermissionAction sait router, mais
	// il refuse d'écrire sur la permission protégée (garde volontaire) : on
	// écrit donc directement ici, en connaissance de cause.
	var granted, skipped int
	for _, key := range actionKeys {
		if legacyColumnsSuperadmin[key] {
			// Colonne legacy : on ne l'écrase que si elle vaut « nil », pour ne
			// pas défaire un réglage explicite.
			query := fmt.Sprintf(
				"UPDATE user_permission SET %s = 'all' WHERE id_user_permission = ? AND (%s IS NULL OR %s = 'nil' OR %s = '')",
				key, key, key, key)
			res, execErr := db.Exec(query, permID)
			if execErr != nil {
				return fmt.Errorf("action legacy %s : %w", key, execErr)
			}
			if n, _ := res.RowsAffected(); n > 0 {
				granted++
			} else {
				skipped++
			}
			continue
		}

		res, execErr := db.Exec(
			`INSERT IGNORE INTO user_permission_action (id_user_permission, action_key, value)
			 VALUES (?, ?, 'all')`, permID, key)
		if execErr != nil {
			return fmt.Errorf("action %s : %w", key, execErr)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			granted++
		} else {
			skipped++
		}
	}

	if granted > 0 {
		logs.Write_Log("INFO", fmt.Sprintf(
			"bootstrap: %d action(s) accordée(s) à %s, %d déjà présente(s)",
			granted, ProtectedUserPermission, skipped))
	}
	return nil
}

// legacyColumnsSuperadmin réplique la table de routage de dbpermission.
//
// Dupliquée plutôt qu'importée : db_permission importe core/database, l'inverse
// créerait un cycle. Elle est figée — ces cinq colonnes sont un héritage du
// modèle LDAP d'origine et aucune n'a été ajoutée depuis — donc le risque de
// dérive est nul, contrairement à la liste d'actions qui, elle, s'allonge.
var legacyColumnsSuperadmin = map[string]bool{
	"none": true, "web_admin": true, "auth": true, "compare": true, "search": true,
}
