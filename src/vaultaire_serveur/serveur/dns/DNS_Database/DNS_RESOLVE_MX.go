package dnsdatabase

import (
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"vaultaire/serveur/logs"
	"database/sql"
	"fmt"
	"strings"
)

func ResolveMXRecords(db *sql.DB, fqdn string) ([]dnsstorage.MXRecord, error) {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

	// 1. Récupérer toutes les zones
	zones, err := GetAllDNSZones(db)
	if err != nil {
		return nil, err
	}

	// 2. Split le nom
	labels := strings.Split(fqdn, ".")

	for i := 0; i < len(labels); i++ {
		zoneCandidate := strings.Join(labels[i:], ".")

		var foundZone *dnsstorage.Zone = nil
		for _, z := range zones {
			if z.ZoneName == zoneCandidate {
				foundZone = &z
				break
			}
		}

		if foundZone != nil {
			relativeLabels := labels[:i]
			relativeName := strings.Join(relativeLabels, ".")
			if relativeName == "" {
				relativeName = "@"
			}

			query := fmt.Sprintf(`
				SELECT data, priority, ttl FROM %s
				WHERE name = ? AND type = 'MX'
				ORDER BY priority ASC;
			`, foundZone.TableName)

			rows, err := db.Query(query, relativeName)
			if err != nil {
				return nil, err
			}
			defer func() {
				if err := rows.Close(); err != nil {
					// Handle or log the error
					logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
				}
			}()

			var records []dnsstorage.MXRecord
			for rows.Next() {
				var rec dnsstorage.MXRecord
				if err := rows.Scan(&rec.Host, &rec.Priority, &rec.TTL); err != nil {
					return nil, err
				}
				records = append(records, rec)
			}

			if len(records) == 0 {
				return nil, fmt.Errorf("❌ Aucun enregistrement MX pour %s dans la zone %s", fqdn, foundZone.ZoneName)
			}

			return records, nil
		}
	}

	return nil, fmt.Errorf("❌ Zone introuvable pour %s", fqdn)
}
