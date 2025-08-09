package dnsdatabase

import (
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
	"database/sql"
	"errors"
	"net"
	"strings"
)

// Résout un FQDN en IP, en cherchant d'abord dans la DB, puis en fallback sur le DNS système
func ResolveFQDNToIP(db *sql.DB, fqdn string) (string, error) {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

	// 1. Récupérer toutes les zones DNS
	zones, err := GetAllDNSZones(db)
	if err != nil {
		return "", err
	}

	// 2. Décomposer le fqdn en labels
	labels := strings.Split(fqdn, ".")

	// 3. Parcourir du plus spécifique au moins spécifique
	for i := 0; i < len(labels); i++ {
		zoneCandidate := strings.Join(labels[i:], ".")

		// Chercher cette zoneCandidate dans la liste des zones
		var foundZone *dnsstorage.Zone = nil
		for _, z := range zones {
			if z.ZoneName == zoneCandidate {
				foundZone = &z
				break
			}
		}

		if foundZone != nil {
			// 4. Construire le nom relatif à la zone
			relativeLabels := labels[:i]
			relativeName := strings.Join(relativeLabels, ".")
			if relativeName == "" {
				relativeName = "@"
			}

			// 5. Chercher dans la table de la zone
			ip, err := queryIPFromZoneTable(db, foundZone.TableName, relativeName)
			if err == nil {
				return ip, nil // IP trouvée
			}
			if errors.Is(err, sql.ErrNoRows) {
				// Une zone a été trouvée mais pas d'entrée correspondante
				return "", errors.New("aucune entrée trouvée pour " + fqdn + " dans la zone " + foundZone.ZoneName)
			}
			// Autre erreur SQL
			return "", err
		}
	}

	// 6. Fallback DNS système standard si aucune zone ne correspond
	ips, err := net.LookupHost(fqdn)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", errors.New("aucune IP trouvée pour " + fqdn)
	}
	return ips[0], nil
}

// queryIPFromZoneTable cherche un enregistrement A dans la table de la zone
func queryIPFromZoneTable(db *sql.DB, tableName, relativeName string) (string, error) {
	query := `
		SELECT data FROM ` + tableName + `
		WHERE name = ? AND type = 'A'
		ORDER BY priority ASC
		LIMIT 1
	`
	var ip string
	err := db.QueryRow(query, relativeName).Scan(&ip)
	if err != nil {
		return "", err
	}
	return ip, nil
}
