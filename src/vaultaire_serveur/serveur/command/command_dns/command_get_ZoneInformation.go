package commanddns

import (
	displaydns "vaultaire/serveur/command/display/display_dns"
	dnsdb "vaultaire/serveur/dns/DNS_Database" // adapte le chemin selon ton projet
	"database/sql"
	"fmt"
	"strings"
)

func command_dns_getZoneInformation_Command_Parser(command_list []string, db *sql.DB) string {
	switch len(command_list) {
	case 1:
		// get_zone → liste toutes les zones
		zones, err := dnsdb.GetAllDNSZones(db)
		if err != nil {
			return fmt.Sprintf("❌ Erreur lors de la récupération des zones : %v", err)
		}
		if len(zones) == 0 {
			return "ℹ️ Aucune zone DNS enregistrée."
		}
		return displaydns.DisplayAllZones(zones)

	case 2:
		// get_zone <zone_name>
		zone := strings.ToLower(command_list[1])
		records, err := dnsdb.GetZoneRecords(db, zone)
		if err != nil {
			return fmt.Sprintf("❌ Erreur lors de la récupération des enregistrements de la zone '%s' : %v", zone, err)
		}
		if len(records) == 0 {
			return fmt.Sprintf("ℹ️ Aucun enregistrement trouvé pour la zone '%s'.", zone)
		}
		return displaydns.DisplayZoneRecords(records, zone)

	default:
		return "❌ Erreur : commande invalide.\nUtilisation :\n- get_zone\n- get_zone <nom_de_zone>"
	}
}
