package display

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"vaultaire/core/storage"

	"github.com/fatih/color"
)

// FormatUsersByStatus renvoie les infos des utilisateurs connectés sous forme de string
func DisplayUsersByStatus(users []storage.UserConnected) string {
	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()
	active := color.New(color.FgGreen).SprintFunc()

	// Buffer pour stocker la sortie formatée
	var sb strings.Builder

	// Ajouter le titre
	sb.WriteString(title("📋 Connected Users") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Utiliser un `tabwriter` pour aligner proprement les colonnes
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 8, 1, ' ', 0)

	// Ajouter les en-têtes
	fmt.Fprintf(w, "%-4s %-15s %-20s %-20s %-10s\n",
		header("ID"),
		header("Username"),
		header("Created At"),
		header("Token Expiry"),
		header("Status"),
	)

	// Ajouter chaque utilisateur
	for _, user := range users {
		// Définir le statut
		status := active("✅ Active")

		// Ajouter les données formatées
		fmt.Fprintf(w, "%-4d %-15s %-20s %-20s %-10s\n",
			user.ID,
			user.Username,
			user.CreatedAt,
			user.TokenExpiry,
			status,
		)
	}

	// Écrire le tableau formaté dans `sb`
	err := w.Flush()
	if err != nil {
		return "Error flushing writer: " + err.Error()
	}
	sb.WriteString(b.String())

	sb.WriteString("--------------------------------------------------\n")

	return sb.String()
}
