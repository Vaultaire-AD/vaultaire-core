package commanddns

import (
	dnsdb "DUCKY/serveur/dns/DNS_Database"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

// command_dns_addRecord_Command_Parser gère la commande d'ajout d'entrée DNS
// Exemple de commande : add_record pipi.caca.test.fr A 192.168.1.1 10
func command_dns_addRecord(command_list []string, db *sql.DB) string {
	if len(command_list) < 5 {
		return "❌ Usage : add_record <name> <type> <data> <ttl> [priority]"
	}

	fqdn := strings.ToLower(command_list[1])
	recordType := strings.ToUpper(command_list[2])
	data := command_list[3]

	ttl, err := strconv.Atoi(command_list[4])
	if err != nil {
		return "❌ TTL invalide, doit être un entier."
	}

	var priority = 100
	if len(command_list) >= 6 {
		priority, err = strconv.Atoi(command_list[5])
		if err != nil {
			return "❌ Priorité invalide, doit être un entier."
		}
	}

	// 🔒 Validation centralisée
	if err := validateDNSRecordInput(db, fqdn, recordType, data); err != nil {
		return err.Error()
	}

	err = dnsdb.AddDNSRecordSmart(db, fqdn, recordType, ttl, data, priority)
	if err != nil {
		return fmt.Sprintf("❌ Erreur ajout enregistrement : %v", err)
	}

	return fmt.Sprintf("✅ Enregistrement ajouté dans la zone la plus spécifique pour %s", fqdn)
}
