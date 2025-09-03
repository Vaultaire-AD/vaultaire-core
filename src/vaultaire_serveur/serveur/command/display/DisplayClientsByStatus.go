package display

import (
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

func DisplayClientsByStatus(clients []storage.ClientConnected) string {
	// Créer un StringBuilder pour accumuler le contenu
	var sb strings.Builder

	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()
	serverIcon := color.New(color.FgGreen).SprintFunc()
	clientIcon := color.New(color.FgCyan).SprintFunc()

	// Ajouter le titre
	sb.WriteString(title("💻 Connected Clients") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)

	// Ajouter les entêtes du tableau
	fmt.Fprintf(w, "%-15s %-15s %-20s %-20s %-10s %-10s %-10s %-10s\n",
		header("Username"),
		header("Type"),
		header("Computeur ID"),
		header("Hostname"),
		header("Serveur"),
		header("CPU"),
		header("RAM"),
		header("OS"),
	)

	// Ajouter les données des clients
	for _, client := range clients {
		serverStatus := clientIcon("🔵 Client")
		if client.Serveur {
			serverStatus = serverIcon("🟢 Serveur")
		}
		fmt.Fprintf(w, "%-15s %-15s %-20s %-20s %-10s %-10d %-10s %-10s\n",
			client.Username,
			client.LogicielType,
			client.ComputeurID,
			client.Hostname,
			serverStatus,
			client.Processeur,
			client.RAM,
			client.OS,
		)
	}

	// Vider le tampon pour s'assurer que tout est écrit dans sb
	err := w.Flush()
	if err != nil {
		return "Error flushing writer: " + err.Error()
	}
	// Ajouter une ligne de séparation
	sb.WriteString("--------------------------------------------------\n")

	// Retourner le contenu accumulé sous forme de chaîne
	return sb.String()
}
