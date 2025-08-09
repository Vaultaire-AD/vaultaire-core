package commanddns

import (
	dnsdatabasego "DUCKY/serveur/dns/DNS_Database"
	"fmt"
	"strings"
)

func command_dns_createNewZone(command_list []string) string {
	if len(command_list) < 2 {
		return "❌ Erreur : commande invalide. Utilisation : create_zone <nom_de_zone>"
	}

	zone := strings.ToLower(command_list[1])

	err := dnsdatabasego.CreateZoneTable(dnsdatabasego.GetDatabase(), zone)
	if err != nil {
		return fmt.Sprintf("❌ Impossible de créer la zone '%s' : %v", zone, err)
	}

	return fmt.Sprintf("✅ Zone '%s' créée avec succès !", zone)
}
