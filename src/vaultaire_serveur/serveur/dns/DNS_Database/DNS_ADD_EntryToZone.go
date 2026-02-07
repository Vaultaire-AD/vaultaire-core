package dnsdatabase

import (
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"database/sql"
	"fmt"
	"strings"
)

// Ajoute un enregistrement DNS dans la zone la plus spécifique trouvée + PTR si nécessaire
func AddDNSRecordSmart(db *sql.DB, fqdn, recordType string, ttl int, data string, priority int) error {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

	zones, err := GetAllDNSZones(db)
	if err != nil {
		return fmt.Errorf("erreur lors de la récupération des zones : %v", err)
	}

	var selectedZone dnsstorage.Zone
	longestMatchLength := 0

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
		return fmt.Errorf("❌ aucune zone ne correspond à '%s'", fqdn)
	}

	relativeName := strings.TrimSuffix(fqdn[:len(fqdn)-len(selectedZone.ZoneName)], ".")
	if relativeName == "" {
		relativeName = "@" // racine de la zone
	}

	tableName := selectedZone.TableName

	// ✅ Vérifier si une entrée A avec ce nom existe déjà
	if strings.ToUpper(recordType) == "A" {
		checkQuery := fmt.Sprintf(`
			SELECT COUNT(*) FROM %s WHERE name = ? AND type = 'A'
		`, tableName)
		var count int
		err := db.QueryRow(checkQuery, relativeName).Scan(&count)
		if err != nil {
			return fmt.Errorf("❌ erreur lors de la vérification des doublons dans %s : %v", tableName, err)
		}
		if count > 0 {
			return fmt.Errorf("⚠️ une entrée A existe déjà avec le nom '%s' dans la zone '%s'", relativeName, selectedZone.ZoneName)
		}
	}

	// 🔽 Insertion
	var res sql.Result
	if priority != 0 {
		query := fmt.Sprintf(`
			INSERT INTO %s (name, type, ttl, data, priority)
			VALUES (?, ?, ?, ?, ?)
		`, tableName)
		res, err = db.Exec(query, relativeName, recordType, ttl, data, priority)
	} else {
		query := fmt.Sprintf(`
			INSERT INTO %s (name, type, ttl, data, priority)
			VALUES (?, ?, ?, ?, ?)
		`, tableName)
		res, err = db.Exec(query, relativeName, recordType, ttl, data, priority)
	}

	if err != nil {
		return fmt.Errorf("❌ erreur lors de l'insertion de l'enregistrement dans la table '%s' : %v", tableName, err)
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("⚠️ aucune ligne insérée pour %s dans %s", fqdn, tableName)
	}

	// ✅ Ajouter un PTR automatique pour les entrées A
	if recordType == "A" {
		err = AddPTRRecord(db, data, fqdn)
		if err != nil {
			fmt.Printf("⚠️ Impossible d'ajouter le PTR : %v\n", err)
		}
	}

	return nil
}
