package commanddns

import (
	dnsdatabase "DUCKY/serveur/dns/DNS_Database"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Validation centrale
func validateDNSRecordInput(db *sql.DB, name, recordType, data string) error {
	recordType = strings.ToUpper(recordType)

	switch recordType {
	case "A":
		if net.ParseIP(data) == nil {
			return fmt.Errorf("❌ IP invalide pour un enregistrement A : %s", data)
		}
		if !isValidFQDN(name) {
			return fmt.Errorf("❌ Nom invalide pour un enregistrement A : %s", name)
		}
		if !dnsdatabase.DomainIsTrue(dnsdatabase.GetZoneFromFQDN(db, name), db) {
			return fmt.Errorf("❌ Domaine inexistant : %s", dnsdatabase.GetZoneFromFQDN(db, name))
		}

	case "CNAME":
		if !isValidFQDN(name) || !isValidFQDN(data) {
			return fmt.Errorf("❌ Nom ou cible invalide pour un CNAME : %s -> %s", name, data)
		}
		if !dnsdatabase.DomainIsTrue(dnsdatabase.GetZoneFromFQDN(db, name), db) {
			return fmt.Errorf("❌ Domaine inexistant : %s", dnsdatabase.GetZoneFromFQDN(db, name))
		}

	case "MX", "NS":
		if !strings.HasPrefix(name, "@.") {
			return fmt.Errorf("❌ Le nom d'un enregistrement %s doit commencer par '@.': %s", recordType, name)
		}
		zone := strings.TrimPrefix(name, "@.")
		if !dnsdatabase.DomainIsTrue(zone, db) {
			return fmt.Errorf("❌ Domaine cible inexistant : %s", zone)
		}
		if !isValidFQDN(data) {
			return fmt.Errorf("❌ Cible invalide pour un %s : %s", recordType, data)
		}

	case "TXT":
		if !strings.HasPrefix(name, "@") && !isValidFQDN(name) {
			return fmt.Errorf("❌ Nom invalide pour TXT : %s", name)
		}
		// Pas de vérification stricte sur le contenu TXT

	default:
		return errors.New("❌ Type d’enregistrement DNS non supporté")
	}

	return nil
}

func isValidFQDN(fqdn string) bool {
	// Simple FQDN validation
	if strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn[:len(fqdn)-1]
	}
	matched, _ := regexp.MatchString(`^([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}$`, fqdn)
	return matched
}
