package dbenrollment

import (
	"database/sql"
	"fmt"

	"vaultaire/core/logs"
)

// CreateTables crée le schéma d'enrôlement s'il n'existe pas.
//
// Appelée à chaque démarrage, idempotente.
func CreateTables(db *sql.DB) error {
	statements := []string{
		// service_enrollment_key : une clé émise par un administrateur.
		//
		// key_hash et non la clé : le secret est affiché une seule fois à
		// l'émission. Le stocker permettrait à quiconque lit la base de
		// s'enrôler comme n'importe quel type de service, y compris celui qui
		// porte le droit d'agir au nom d'un tiers.
		//
		// client_type est en TEXTE et sans contrainte vers un catalogue : le
		// catalogue est du code (core/clienttype), pas une table. La validité
		// du type est vérifiée à l'émission et re-vérifiée à la consommation —
		// un type retiré du code entre les deux doit invalider la clé, pas
		// enrôler un service que plus rien ne décrit.
		`CREATE TABLE IF NOT EXISTS service_enrollment_key (
			id_key      INT AUTO_INCREMENT PRIMARY KEY,
			key_hash    CHAR(64)     NOT NULL UNIQUE,
			label       VARCHAR(128) NOT NULL DEFAULT '',
			client_type VARCHAR(64)  NOT NULL,
			max_uses    INT          NOT NULL,
			used_count  INT          NOT NULL DEFAULT 0,
			expires_at  DATETIME     NOT NULL,
			created_by  VARCHAR(255) NOT NULL,
			created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
			revoked_by  VARCHAR(255) NULL,
			revoked_at  DATETIME     NULL,
			INDEX idx_enrollment_type (client_type),
			INDEX idx_enrollment_live (revoked_at, expires_at)
		);`,

		// service_enrollment_use : une ligne par consommation.
		//
		// Sans cette table, on ne peut pas répondre à « quels services sont
		// entrés par cette clé ? » le jour où l'on découvre qu'elle a fuité —
		// et c'est précisément le jour où la question se pose.
		//
		// ON DELETE CASCADE est acceptable ici, contrairement à la révocation :
		// supprimer une clé d'enrôlement est une décision d'administration, pas
		// la disparition du sujet d'une trace d'audit. Le client créé, lui,
		// survit dans id_logiciels.
		`CREATE TABLE IF NOT EXISTS service_enrollment_use (
			id_use       INT AUTO_INCREMENT PRIMARY KEY,
			d_id_key     INT          NOT NULL,
			computeur_id VARCHAR(255) NOT NULL,
			client_type  VARCHAR(64)  NOT NULL,
			source_ip    VARCHAR(45)  NULL,
			used_at      DATETIME     DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_enrollment_use_key (d_id_key),
			FOREIGN KEY (d_id_key) REFERENCES service_enrollment_key(id_key) ON DELETE CASCADE
		);`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"dbenrollment: création de table échouée : "+err.Error())
			return fmt.Errorf("création du schéma d'enrôlement : %w", err)
		}
	}
	return nil
}
