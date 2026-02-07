package dnsdatabase

import (
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"database/sql"
	"fmt"
	"strings"
)

// ResolveCNAME récupère la cible d'un enregistrement CNAME pour un FQDN donné
func ResolveCNAME(db *sql.DB, fqdn string) (string, error) {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

	// Récupérer toutes les zones enregistrées
	zones, err := GetAllDNSZones(db)
	if err != nil {
		return "", fmt.Errorf("erreur lors de la récupération des zones : %v", err)
	}

	var selectedZone dnsstorage.Zone
	longestMatchLength := 0

	// Trouver la zone la plus spécifique correspondant au fqdn
	for _, zone := range zones {
		zoneName := strings.ToLower(zone.ZoneName)
		if strings.HasSuffix(fqdn, zoneName) {
			if len(fqdn) == len(zoneName) || fqdn[len(fqdn)-len(zoneName)-1] == '.' {
				if len(zoneName) > longestMatchLength {
					longestMatchLength = len(zoneName)
					selectedZone = zone
				}
			}
		}
	}

	if longestMatchLength == 0 {
		return "", fmt.Errorf("❌ aucune zone ne correspond à '%s'", fqdn)
	}

	relativeName := strings.TrimSuffix(fqdn[:len(fqdn)-len(selectedZone.ZoneName)], ".")
	if relativeName == "" {
		relativeName = "@" // racine de la zone
	}

	query := fmt.Sprintf(`SELECT data FROM %s WHERE name = ? AND type = 'CNAME' LIMIT 1`, selectedZone.TableName)

	var target string
	err = db.QueryRow(query, relativeName).Scan(&target)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("❌ aucun enregistrement CNAME trouvé pour %s", fqdn)
	}
	if err != nil {
		return "", fmt.Errorf("erreur lors de la récupération du CNAME : %v", err)
	}

	return target, nil
}
