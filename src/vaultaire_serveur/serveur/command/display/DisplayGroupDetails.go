package display

import (
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

// DisplayGroupDetails renvoie les détails des groupes sous forme de chaîne formatée
func DisplayGroupDetails(groupDetails []storage.GroupDetails) string {
	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	var sb strings.Builder

	sb.WriteString(title("📊 Group Details") + "\n")
	sb.WriteString("-------------------------------------------------------------------------------\n")

	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 8, 1, ' ', 0)

	// En-têtes
	fmt.Println(w, "%-20s %-20s %-15s %-20s %-10s %-10s\n",
		header("Group Name"),
		header("Domain"),
		header("Logiciel Perm."),
		header("User Perm."),
		header("Users"),
		header("Clients"),
	)

	// Données
	for _, group := range groupDetails {
		fmt.Println(w, "%-20s %-20s %-15d %-20d %-10d %-10d\n",
			group.GroupName,
			group.DomainName,
			group.LogicielPermissionCount,
			group.UserPermissionCount,
			group.UserCount,
			group.ClientCount,
		)
	}

	err := w.Flush()
	if err != nil {
		return "Error flushing writer: " + err.Error()
	}
	sb.WriteString(b.String())
	sb.WriteString("-------------------------------------------------------------------------------\n")

	return sb.String()
}
