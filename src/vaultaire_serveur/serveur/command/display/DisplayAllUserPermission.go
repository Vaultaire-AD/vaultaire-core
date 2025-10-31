package display

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

func DisplayAllUserPermissions(permissions []storage.UserPermission) string {
	var sb strings.Builder

	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	sb.WriteString(title("🔑 Liste de toutes les Permissions Utilisateur") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)

	// En-têtes avec les colonnes pour chaque champ booléen
	fmt.Fprintf(w, "%-5s %-20s %-30s %-6s %-6s %-8s %-8s %-6s %-6s\n",
		header("ID"),
		header("Nom"),
		header("Description"),
		header("None"),
		header("Auth"),
		header("Compare"),
		header("Search"),
		header("Read"),
		header("Write"),
	)

	for _, p := range permissions {
		fmt.Fprintf(w, "%-5d %-20s %-30s %-6s %-6s %-8s %-8s %-6s %-6s\n",
			p.ID,
			p.Name,
			p.Description,
			p.None,
			p.Auth,
			p.Compare,
			p.Search,
			p.Read,
			p.Write,
		)
	}

	err := w.Flush()
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de l'écriture du tableau: "+err.Error())
		return "Erreur lors de l'affichage des permissions."
	}
	sb.WriteString("--------------------------------------------------\n")

	return sb.String()
}
