package display

import (
	"vaultaire/serveur/storage"
	"fmt"
	"strings"

	"github.com/fatih/color"
)

func DisplayClientPermission(permission storage.ClientPermission) string {
	var sb strings.Builder

	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	label := color.New(color.FgYellow, color.Bold).SprintFunc()

	sb.WriteString(title("🔑 Permission Client : "+permission.Name) + "\n")
	sb.WriteString("-----------------------------------------\n")
	sb.WriteString(fmt.Sprintf("%s: %d\n", label("ID"), permission.ID))
	sb.WriteString(fmt.Sprintf("%s: %t\n", label("Admin"), permission.IsAdmin))
	sb.WriteString("-----------------------------------------\n")

	return sb.String()
}
