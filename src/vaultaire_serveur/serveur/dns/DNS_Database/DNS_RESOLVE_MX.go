package dnsdatabase

import (
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
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
			defer rows.Close()

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
