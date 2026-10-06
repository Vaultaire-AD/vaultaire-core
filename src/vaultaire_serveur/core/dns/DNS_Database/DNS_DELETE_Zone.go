package dnsdatabase

import (
	"database/sql"
	"fmt"
)

func DeleteZone(db *sql.DB, zoneName string) error {
	// Nom de la table correspondant à la zone, validé et cité (TO-DO 105) :
	// c'est la seule requête qui DÉTRUIT une table.
	table, err := tableDeZone(zoneName)
	if err != nil {
		return err
	}

	// Supprimer la table de zone
	if _, err := db.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, table)); err != nil {
		return fmt.Errorf("❌ erreur suppression de la table %s : %v", table, err)
	}

	// Supprimer l'entrée de dns_zones
	_, err = db.Exec(`DELETE FROM dns_zones WHERE zone_name = ?`, zoneName)
	if err != nil {
		return fmt.Errorf("❌ erreur suppression de l'entrée dns_zones pour '%s' : %v", zoneName, err)
	}

	return nil
}
