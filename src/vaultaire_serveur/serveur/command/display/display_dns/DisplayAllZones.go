package displaydns

import (
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

func DisplayAllZones(zones []dnsstorage.Zone) string {
	var sb strings.Builder

	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	sb.WriteString(title("🌐 Liste des zones DNS enregistrées") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)
	fmt.Fprintf(w, "%-30s %-30s\n", header("Zone"), header("Nom de la table"))

	for _, zone := range zones {
		fmt.Fprintf(w, "%-30s %-30s\n", zone.ZoneName, zone.TableName)
	}

	w.Flush()
	sb.WriteString("--------------------------------------------------\n")
	return sb.String()
}
