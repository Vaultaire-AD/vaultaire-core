package dbauthpolicy

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

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
