package displaydns

import (
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
	"DUCKY/serveur/logs"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

func DisplayZoneRecords(records []dnsstorage.ZoneRecord, zone string) string {
	var sb strings.Builder

	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	sb.WriteString(title(fmt.Sprintf("📂 Enregistrements DNS pour la zone : %s", zone)) + "\n")
	sb.WriteString("------------------------------------------------------------------------\n")

	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)
	_, err := fmt.Fprintf(w, "%-25s %-8s %-6s %-20s %-10s\n",
		header("Nom"),
		header("Type"),
		header("TTL"),
		header("Données"),
		header("Priorité"),
	)
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de l'écriture des en-têtes: "+err.Error())
		return "Erreur lors de l'affichage des enregistrements DNS."
	}
	for _, record := range records {
		priority := "—"
		if record.Priority.Valid {
			priority = fmt.Sprintf("%d", record.Priority.Int64)
		}
		fmt.Println(w, "%-25s %-8s %-6d %-20s %-10s\n",
			record.Name,
			record.Type,
			record.TTL,
			record.Data,
			priority,
		)
	}

	err = w.Flush()
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de l'écriture des enregistrements DNS: "+err.Error())
		return "Erreur lors de l'affichage des enregistrements DNS."
	}
	sb.WriteString("------------------------------------------------------------------------\n")
	return sb.String()
}
