package dnsdatabase

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
)

// Crée une table de zone et l'enregistre dans dns_zones
func CreateZoneTable(db *sql.DB, zone string) error {
	// Nettoyer et créer un nom de table sûr
	safeTableName := "zone_" + strings.ReplaceAll(zone, ".", "_")

	// 1. Créer la table de la zone DNS si elle n'existe pas
	createTableQuery := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		name VARCHAR(255) NOT NULL,
		type VARCHAR(10) NOT NULL,
		ttl INT DEFAULT 3600,
		data TEXT NOT NULL,
		priority INT DEFAULT NULL
	);`, safeTableName)

	_, err := db.Exec(createTableQuery)
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
		log.Printf("✅ Zone '%s' enregistrée dans la table '%s'\n", zone, safeTableName)
	} else {
		log.Printf("ℹ️ Zone '%s' déjà enregistrée avec la table '%s'\n", zone, existingTable)
	}

	return nil
}
