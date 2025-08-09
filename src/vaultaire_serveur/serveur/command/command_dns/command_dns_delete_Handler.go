package commanddns

import (
	dnsdatabasego "DUCKY/serveur/dns/DNS_Database"
	"fmt"
	"strings"
)

func command_dns_delete(command_list []string) string {
	if len(command_list) < 2 {
		return `❌ Erreur : commande invalide.

Utilisation :
  delete zone <nom.zone>
  delete record <fqdn> <type>
  delete ptr <ip>`
	}

	db := dnsdatabasego.GetDatabase()
	if db == nil {
		return "❌ Base de données non initialisée."
	}

	switch command_list[1] {
	case "zone":
		if len(command_list) < 3 {
			return "❌ Erreur : nom de zone manquant. Utilisation : delete zone <nom.zone>"
		}
		zone := strings.ToLower(command_list[2])
		err := dnsdatabasego.DeleteZone(db, zone)
		if err != nil {
			return fmt.Sprintf("❌ Échec suppression zone '%s' : %v", zone, err)
		}
		return fmt.Sprintf("✅ Zone '%s' supprimée avec succès.", zone)

	case "record":
		if len(command_list) < 4 {
			return "❌ Erreur : arguments manquants. Utilisation : delete record <fqdn> <type>"
		}
		fqdn := strings.ToLower(command_list[2])
		recordType := strings.ToUpper(command_list[3])
		err := dnsdatabasego.DeleteDNSRecord(db, fqdn, recordType)
		if err != nil {
			return fmt.Sprintf("❌ Échec suppression enregistrement '%s' (%s) : %v", fqdn, recordType, err)
		}
		return fmt.Sprintf("✅ Enregistrement '%s' de type %s supprimé avec succès.", fqdn, recordType)

	case "ptr":
		if len(command_list) < 3 {
			return "❌ Erreur : IP manquante. Utilisation : delete ptr <ip>"
		}
		ip := command_list[2]
		err := dnsdatabasego.DeletePTRRecordByIP(db, ip)
		if err != nil {
			return fmt.Sprintf("❌ Échec suppression PTR pour IP '%s' : %v", ip, err)
		}
		return fmt.Sprintf("✅ Enregistrement PTR pour IP '%s' supprimé avec succès.", ip)

	default:
		return `❌ Option invalide.

Utilisation :
  delete zone <nom.zone>
  delete record <fqdn> <type>
  delete ptr <ip>`
	}
}
