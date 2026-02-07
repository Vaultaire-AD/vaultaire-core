package dnsdatabase

import (
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"database/sql"
	"fmt"
	"strings"
)

func DeleteDNSRecord(db *sql.DB, fqdn string, recordType string) error {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))

	// Trouver la zone correspondante
	zones, err := GetAllDNSZones(db)
	if err != nil {
		return fmt.Errorf("❌ échec récupération zones : %v", err)
	}

	var selectedZone dnsstorage.Zone
	longestMatch := 0
	for _, zone := range zones {
		if strings.HasSuffix(fqdn, zone.ZoneName) {
			if len(fqdn) == len(zone.ZoneName) || fqdn[len(fqdn)-len(zone.ZoneName)-1] == '.' {
				if len(zone.ZoneName) > longestMatch {
					longestMatch = len(zone.ZoneName)
					selectedZone = zone
				}
			}
		}
	}

	if longestMatch == 0 {
		return fmt.Errorf("❌ aucune zone trouvée pour %s", fqdn)
	}

	// Calculer le nom relatif à la zone
	relativeName := strings.TrimSuffix(fqdn[:len(fqdn)-len(selectedZone.ZoneName)], ".")
	if relativeName == "" {
		relativeName = "@"
	}

	query := fmt.Sprintf(`DELETE FROM %s WHERE name = ? AND type = ?`, selectedZone.TableName)
	res, err := db.Exec(query, relativeName, recordType)
	if err != nil {
		return fmt.Errorf("❌ erreur suppression enregistrement : %v", err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("ℹ️ aucun enregistrement %s trouvé dans %s pour %s", recordType, selectedZone.TableName, fqdn)
	}

	// Supprimer aussi le PTR si c'était un enregistrement A
	if recordType == "A" {
		err := DeletePTRRecordByIP(db, fqdn)
		if err != nil {
			fmt.Printf("⚠️ Erreur suppression PTR liée : %v\n", err)
		}
	}

	return nil
}
