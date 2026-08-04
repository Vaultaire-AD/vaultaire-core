// Package db_authpolicy porte le stockage du second facteur (TOTP) et de la
// politique d'expiration des mots de passe.
//
// Les deux sujets vivent dans le même paquet parce qu'ils répondent à la même
// question — « cette authentification est-elle encore recevable ? » — et sont
// interrogés par les mêmes trois chemins : bind LDAP, login web, et Ducky, qui
// porte PAM. Les séparer obligerait chaque chemin à connaître deux paquets et à
// composer lui-même les deux réponses, ce qui est exactement le genre de
// composition qu'on finit par oublier sur le troisième appelant.
//
// CE PAQUET NE DÉCIDE RIEN. Il lit et écrit. La décision — expiré, en préavis,
// valide — appartient à core/auth/passwordpolicy, qui n'a pas d'accès direct à
// la base et reçoit ses données d'ici. C'est ce qui permet de tester la règle
// sans base de données.
package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"regexp"

	"vaultaire/core/logs"
)

// identifierPattern borne les noms de table et de colonne acceptés par
// ensureColumn.
//
// Ces noms ne peuvent pas être passés en paramètre de requête préparée : MySQL
// n'accepte de placeholder que pour des valeurs, pas pour des identifiants. La
// concaténation est donc inévitable, et c'est ce motif qui la rend sûre. Tous
// les appelants actuels passent des constantes du code — mais un futur appelant
// qui passerait une chaîne venue d'ailleurs se heurterait ici plutôt qu'à une
// injection.
var identifierPattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

// CreateSchema installe les colonnes et tables nécessaires.
//
// Idempotent, appelé à chaque démarrage. Les bases existantes reçoivent les
// nouvelles colonnes sans script de migration à lancer à la main — le projet
// n'a pas de mécanisme de migration versionnée, et en introduire un pour cinq
// colonnes coûterait plus cher que ce qu'il rapporte.
func CreateSchema(db *sql.DB) error {
	// ----- Second facteur, porté par le compte -----
	//
	// Le secret vit dans `users` et non dans une table dédiée : il a exactement
	// la même durée de vie que le compte, et une table séparée demanderait une
	// clé étrangère dont le seul effet serait de recopier ce cycle de vie.
	//
	// Différence assumée avec le kill switch, où la trace doit au contraire
	// survivre à la suppression du compte : ici, un secret TOTP orphelin n'a
	// aucune valeur d'audit et tout d'un secret qui traîne.
	columns := []struct{ table, column, definition string }{
		// Secret partagé, encodé en base32. 32 caractères pour 160 bits, ce que
		// recommande la RFC 4226 §4 pour HMAC-SHA1.
		{"users", "mfa_secret", "VARCHAR(64) NULL"},

		// Distinct de la présence du secret. Entre la génération du secret et la
		// validation du premier code, le compte a un secret mais PAS de second
		// facteur actif : sans ce drapeau, un enrôlement abandonné à mi-chemin
		// verrouillerait le compte sur un secret que personne n'a enregistré
		// dans son application.
		{"users", "mfa_enabled", "BOOLEAN NOT NULL DEFAULT FALSE"},

		{"users", "mfa_enrolled_at", "DATETIME NULL"},

		// Dernier pas de temps consommé, pour l'anti-rejeu.
		//
		// En base et non en mémoire : un code TOTP reste valide 30 à 90 secondes
		// selon la tolérance, ce qui laisse largement le temps de redémarrer le
		// serveur. Un registre en mémoire rendrait donc un code rejouable à
		// chaque redémarrage — et le redémarrage est précisément ce qu'un
		// attaquant peut provoquer.
		{"users", "mfa_last_counter", "BIGINT NULL"},

		// Date du dernier changement de mot de passe, base du calcul
		// d'expiration.
		{"users", "password_changed_at", "DATETIME NULL"},

		// Exigence de second facteur portée par le groupe.
		//
		// Cohérent avec le reste du modèle — permissions, GPO et appartenances
		// passent déjà par les groupes — et surtout : un nouvel arrivant placé
		// dans le groupe des administrateurs est soumis au MFA du seul fait de
		// son entrée, sans que personne ait à y penser. Un drapeau par compte
		// aurait exigé un geste à chaque création, donc aurait été oublié.
		{"groups", "mfa_required", "BOOLEAN NOT NULL DEFAULT FALSE"},
	}

	for _, c := range columns {
		if err := ensureColumn(db, c.table, c.column, c.definition); err != nil {
			return err
		}
	}

	// ----- Réglages globaux -----
	//
	// Une table clé/valeur plutôt qu'une table à colonnes typées. Le projet n'a
	// aujourd'hui aucun endroit où poser un réglage serveur, et il en viendra
	// d'autres : ajouter une ligne coûte moins qu'une colonne et une migration.
	//
	// La contrepartie — pas de typage en base — est assumée : la lecture est
	// centralisée dans settings.go, qui valide et borne chaque valeur. Aucun
	// appelant ne lit cette table directement.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS server_settings (
			setting_key   VARCHAR(64) PRIMARY KEY,
			setting_value VARCHAR(255) NOT NULL,
			updated_by    VARCHAR(255) NULL,
			updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		);`); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: création de server_settings échouée : "+err.Error())
		return fmt.Errorf("création de server_settings : %w", err)
	}

	if err := backfillPasswordDates(db); err != nil {
		return err
	}

	logs.Write_Log("INFO", "authpolicy: schéma vérifié")
	return nil
}

// ensureColumn ajoute une colonne si elle n'existe pas déjà.
//
// `ALTER TABLE ... ADD COLUMN` n'est pas idempotent sous MySQL : il échoue avec
// l'erreur 1060 si la colonne existe. On pourrait avaler ce code d'erreur
// précis, mais cela reviendrait à traiter le cas normal — un serveur qui
// redémarre — comme une erreur, et à masquer du même geste une vraie 1060 venue
// d'ailleurs. La consultation d'information_schema dit ce qu'on veut savoir.
func ensureColumn(db *sql.DB, table, column, definition string) error {
	if !identifierPattern.MatchString(table) || !identifierPattern.MatchString(column) {
		return fmt.Errorf("identifiant de schéma refusé : %s.%s", table, column)
	}

	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
		table, column).Scan(&count)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: inspection de "+table+"."+column+" échouée : "+err.Error())
		return fmt.Errorf("inspection de %s.%s : %w", table, column, err)
	}
	if count > 0 {
		return nil
	}

	if _, err := db.Exec("ALTER TABLE `" + table + "` ADD COLUMN `" + column + "` " + definition); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: ajout de "+table+"."+column+" échoué : "+err.Error())
		return fmt.Errorf("ajout de %s.%s : %w", table, column, err)
	}

	logs.Write_Log("INFO", "authpolicy: colonne "+table+"."+column+" ajoutée")
	return nil
}

// backfillPasswordDates donne une date de référence aux comptes qui n'en ont
// pas.
//
// Sans cela, tous les comptes existants auraient `password_changed_at` à NULL au
// premier démarrage suivant la mise à jour. Deux lectures possibles de ce NULL,
// toutes deux mauvaises : « jamais changé, donc infiniment expiré » verrouille
// l'annuaire entier d'un coup, et « inconnu, donc valide » crée une population
// de comptes qui n'expirera jamais.
//
// La date de création est la seule approximation défendable : c'est le moment où
// le mot de passe initial a été posé. Un compte créé il y a deux ans avec une
// politique à 90 jours se retrouve donc expiré dès l'activation de la politique
// — ce qui est le comportement correct, et la raison pour laquelle la politique
// est désactivée par défaut (durée 0).
func backfillPasswordDates(db *sql.DB) error {
	res, err := db.Exec(`UPDATE users SET password_changed_at = created_at
		WHERE password_changed_at IS NULL`)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"authpolicy: initialisation de password_changed_at échouée : "+err.Error())
		return fmt.Errorf("initialisation de password_changed_at : %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		logs.Write_Log("INFO", fmt.Sprintf(
			"authpolicy: %d compte(s) initialisé(s) sur leur date de création", n))
	}
	return nil
}
