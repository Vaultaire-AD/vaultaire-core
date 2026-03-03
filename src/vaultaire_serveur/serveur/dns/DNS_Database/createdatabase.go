package dnsdatabase

import (
	"database/sql"
	"fmt"

	"vaultaire/serveur/logs"
)

// Initialise la table des enregistrements PTR
func InitPTRTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS ptr_records (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		ip VARCHAR(45) NOT NULL UNIQUE,
		name VARCHAR(255) NOT NULL
	);`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("échec création table ptr_records : %v", err)
	}

	logs.Write_Log("INFO", "dnsdb: table 'ptr_records' ready")
	return nil
}

// Crée la table de correspondance zone <-> nom de table
func InitZonesTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS dns_zones (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		zone_name VARCHAR(255) NOT NULL UNIQUE,
		table_name VARCHAR(255) NOT NULL UNIQUE
	);`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("échec création table dns_zones : %v", err)
	}

	logs.Write_Log("INFO", "dnsdb: table 'dns_zones' ready")
	return nil
}
