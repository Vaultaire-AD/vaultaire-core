package display

import (
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

func DisplayAllClientPermissions(permissions []storage.ClientPermission) string {
	// Créer un StringBuilder pour accumuler le contenu
	var sb strings.Builder

	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	// Ajouter le titre
	sb.WriteString(title("🔑 Liste de toutes les Permissions Client") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)

	// Ajouter les en-têtes
	fmt.Fprintf(w, "%-15s %-25s %-25s\n",
		header("ID Permission Client"),
		header("Nom de la Permission Client"),
		header("Admin"),
	)

	// Ajouter chaque permission client
	for _, permission := range permissions {
		fmt.Fprintf(w, "%-15d %-25s %-15t\n",
			permission.ID,
			permission.Name,
			permission.IsAdmin,
		)
	}

	// Vider le tampon pour s'assurer que tout est écrit dans sb
	w.Flush()

	// Ajouter une ligne de séparation
	sb.WriteString("--------------------------------------------------\n")

	return sb.String()
}
