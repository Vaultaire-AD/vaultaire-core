package display

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"vaultaire/core/logs"
	"vaultaire/core/storage"

	"github.com/fatih/color"
)

func DisplayAllUserPermissions(permissions []storage.UserPermission) string {
	var sb strings.Builder

	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	sb.WriteString(title("🔑 Liste de toutes les Permissions Utilisateur") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)

	fmt.Fprintf(w, "%-5s %-20s %-30s %-6s %-6s %-8s %-8s %-8s\n",
		header("ID"),
		header("Nom"),
		header("Description"),
		header("None"),
		header("Auth"),
		header("Compare"),
		header("Search"),
		header("WebAdmin"),
	)

	for _, p := range permissions {
		fmt.Fprintf(w, "%-5d %-20s %-30s %-6s %-6s %-8s %-8s %-8s\n",
			p.ID,
			p.Name,
			p.Description,
			p.None,
			p.Auth,
			p.Compare,
			p.Search,
			p.Web_admin,
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
