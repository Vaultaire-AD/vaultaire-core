package dnsdatabase

import (
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
	"strings"
)

// getZoneFromFQDN cherche la zone la plus spécifique contenue dans le FQDN
func GetZoneFromFQDN(db *sql.DB, fqdn string) string {
	// Charger toutes les zones
	rows, err := db.Query(`SELECT zone_name FROM dns_zones`)
	if err != nil {
		return ""
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
		}
	}()

	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

	var candidates []string
	for rows.Next() {
		var zone string
		if err := rows.Scan(&zone); err != nil {
			return ""
		}
		zone = strings.ToLower(zone)
		if strings.HasSuffix(fqdn, "."+zone) || fqdn == zone {
			candidates = append(candidates, zone)
		}
	}

	if len(candidates) == 0 {
		return "" // Aucun match trouvé
	}

	// Trouver la zone la plus spécifique (plus longue)
	best := candidates[0]
	for _, z := range candidates[1:] {
		if len(z) > len(best) {
			best = z
		}
	}

	return best
}
