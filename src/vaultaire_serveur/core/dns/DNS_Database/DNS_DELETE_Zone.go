package dnsdatabase

import (
	"database/sql"
	"fmt"
	"strings"
)

func DeleteZone(db *sql.DB, zoneName string) error {
	// Nom de la table correspondant à la zone
	safeTableName := "zone_" + strings.ReplaceAll(zoneName, ".", "_")

	// Supprimer la table de zone
	_, err := db.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, safeTableName))
	if err != nil {
		return fmt.Errorf("❌ erreur suppression de la table %s : %v", safeTableName, err)
	}

	// Supprimer l'entrée de dns_zones
	_, err = db.Exec(`DELETE FROM dns_zones WHERE zone_name = ?`, zoneName)
	if err != nil {
		return fmt.Errorf("❌ erreur suppression de l'entrée dns_zones pour '%s' : %v", zoneName, err)
	}

	return nil
}
