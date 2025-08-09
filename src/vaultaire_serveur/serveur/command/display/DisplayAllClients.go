package display

import (
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

func DisplayAllClients(clients []storage.GetClientsByPermission) string {
	// Créer un StringBuilder pour accumuler le contenu
	var sb strings.Builder

	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	// Ajouter le titre
	sb.WriteString(title("💻 Liste de tous les Clients (Logiciels)") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)

	// Ajouter les en-têtes
	fmt.Fprintf(w, "%-15s %-25s %-15s %-15s %-10s %-10s %-15s %-10s\n",
		header("ID Logiciel"),
		header("Logiciel Type"),
		header("Computeur ID"),
		header("Hostname"),
		header("Serveur"),
		header("Processeur"),
		header("RAM"),
		header("OS"),
	)

	// Ajouter chaque client (logiciel)
	for _, client := range clients {
		serveurStatus := "Non"
		if client.Serveur {
			serveurStatus = "Oui"
		}

		// Ajouter les détails du client (logiciel)
		fmt.Fprintf(w, "%-15d %-25s %-15s %-15s %-10s %-10d %-15s %-10s\n",
			client.ID,
			client.LogicielType,
			client.ComputeurID,
			client.Hostname,
			serveurStatus,
			client.Processeur,
			client.RAM,
			client.OS,
		)
	}

	// Vider le tampon pour s'assurer que tout est écrit dans sb
	w.Flush()

	// Ajouter une ligne de séparation
	sb.WriteString("--------------------------------------------------\n")

	// Retourner le contenu accumulé sous forme de chaîne
	return sb.String()
}
