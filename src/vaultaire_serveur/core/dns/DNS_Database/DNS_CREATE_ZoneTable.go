package dnsdatabase

import (
	"database/sql"
	"fmt"
	"vaultaire/core/logs"
)

// Crée une table de zone et l'enregistre dans dns_zones
func CreateZoneTable(db *sql.DB, zone string) error {
	// Nom de table validé (liste blanche) puis cité (TO-DO 105).
	safeTableName, err := NomDeTable(zone)
	if err != nil {
		return err
	}
	table, err := identifiantTable(safeTableName)
	if err != nil {
		return err
	}

	// 1. Créer la table de la zone DNS si elle n'existe pas
	createTableQuery := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		name VARCHAR(255) NOT NULL,
		type VARCHAR(10) NOT NULL,
		ttl INT DEFAULT 3600,
		data TEXT NOT NULL,
		priority INT DEFAULT NULL
	);`, table)

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return fmt.Errorf("erreur création de la table %s : %v", safeTableName, err)
	}

	// 2. Vérifier si la zone est déjà enregistrée dans dns_zones
	var existingTable string
	err = db.QueryRow(`SELECT table_name FROM dns_zones WHERE zone_name = ?`, zone).Scan(&existingTable)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("erreur lors de la vérification de la zone dans dns_zones : %v", err)
	}

	// 3. Si pas trouvée, insérer la liaison zone <-> table
	if err == sql.ErrNoRows {
		_, err = db.Exec(`INSERT INTO dns_zones (zone_name, table_name) VALUES (?, ?)`, zone, safeTableName)
		if err != nil {
			return fmt.Errorf("erreur insertion dans dns_zones : %v", err)
		}
		logs.Write_Log("INFO", fmt.Sprintf("dns : zone %s enregistrée (table %s)", zone, safeTableName))
	} else {
		logs.Write_Log("DEBUG", fmt.Sprintf("dns : zone %s déjà enregistrée (table %s)", zone, existingTable))
	}

	return nil
}
