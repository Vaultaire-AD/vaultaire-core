package display

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"vaultaire/core/storage"

	"github.com/fatih/color"
)

// FormatUsersByGroup renvoie les informations des utilisateurs dans un groupe donné sous forme de chaîne
func DisplayUsersByGroup(groupName string, users []storage.DisplayUsersByGroup) string {
	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()
	connected := color.New(color.FgGreen).SprintFunc()
	disconnected := color.New(color.FgRed).SprintFunc()

	// Utilisation d'un StringBuilder pour accumuler la sortie
	var sb strings.Builder

	// Ajouter le titre
	sb.WriteString(title("👥 Users in Group: "+groupName) + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 8, 1, ' ', 0)

	// Ajouter les en-têtes
	fmt.Fprintf(w, "%-20s %-15s %-10s\n",
		header("Username"),
		header("Date of Birth"),
		header("Status"),
	)

	// Ajouter chaque utilisateur avec leur statut
	for _, user := range users {
		status := disconnected("❌ Offline")
		if user.Connected {
			status = connected("✅ Online")
		}

		// Ajouter les données formatées
		fmt.Fprintf(w, "%-20s %-15s %-10s\n",
			user.Username,
			user.DateOfBirth,
			status,
		)
	}

	// Vider le tampon et ajouter au StringBuilder
	err := w.Flush()
	if err != nil {
		return "Error flushing writer: " + err.Error()
	}
	sb.WriteString(b.String())

	// Ajouter la ligne de séparation
	sb.WriteString("--------------------------------------------------\n")

	// Retourner la chaîne accumulée
	return sb.String()
}
