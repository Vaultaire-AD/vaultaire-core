package displaydns

import (
	"fmt"
	"strings"
	"text/tabwriter"
	dnsstorage "vaultaire/core/dns/DNS_Storage"
	"vaultaire/core/logs"

	"github.com/fatih/color"
)

func DisplayAllZones(zones []dnsstorage.Zone) string {
	var sb strings.Builder

	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	sb.WriteString(title("🌐 Liste des zones DNS enregistrées") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)
	_, err := fmt.Fprintf(w, "%-30s %-30s\n", header("Zone"), header("Nom de la table"))
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de l'écriture des en-têtes: "+err.Error())
		return "Erreur lors de l'affichage des zones DNS."
	}

	for _, zone := range zones {
		_, err := fmt.Fprintf(w, "%-30s %-30s\n", zone.ZoneName, zone.TableName)
		if err != nil {
			logs.Write_Log("ERROR", "Erreur lors de l'écriture des zones DNS: "+err.Error())
			return "Erreur lors de l'affichage des zones DNS."
		}
	}

	err = w.Flush()
	if err != nil {
		return "Error flushing writer: " + err.Error()
	}
	sb.WriteString("--------------------------------------------------\n")
	return sb.String()
}
