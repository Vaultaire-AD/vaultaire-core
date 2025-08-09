package display

import (
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

func DisplayClientsByGroup(clients []storage.GetClientsByGroup, groupName string) string {
	// Créer un StringBuilder pour accumuler le contenu
	var sb strings.Builder

	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	// Ajouter le titre
	sb.WriteString(title("💻 Clients in Group: "+groupName) + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)

	// Ajouter les en-têtes
	fmt.Println(w, "%-10s %-15s %-20s %-15s %-10s %-15s %-10s\n",
		header("Client ID"),
		header("Type"),
		header("Computeur ID"),
		header("Hostname"),
		header("Serveur"),
		header("Processeur"),
		header("RAM"),
	)

	// Ajouter chaque client
	for _, client := range clients {
		serveur := "No"
		if client.Serveur {
			serveur = "Yes"
		}

		// Ajouter les informations du client
		fmt.Println(w, "%-10d %-15s %-20s %-15s %-10s %-15d %-10s\n",
			client.ID,
			client.LogicielType,
			client.ComputeurID,
			client.Hostname,
			serveur,
			client.Processeur,
			client.RAM,
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
