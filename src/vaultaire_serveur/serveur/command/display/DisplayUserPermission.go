package display

import (
	"DUCKY/serveur/storage"
	"fmt"
	"strings"

	"github.com/fatih/color"
)

func DisplayUserPermission(permission storage.UserPermission) string {
	var sb strings.Builder

	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	label := color.New(color.FgYellow, color.Bold).SprintFunc()

	sb.WriteString(title("👤 Permission Utilisateur : "+permission.Name) + "\n")
	sb.WriteString("-------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("%s: %d\n", label("ID"), permission.ID))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("Description"), permission.Description))
	sb.WriteString(fmt.Sprintf("%s: %t\n", label("None"), permission.None))
	sb.WriteString(fmt.Sprintf("%s: %t\n", label("Auth"), permission.Auth))
	sb.WriteString(fmt.Sprintf("%s: %t\n", label("Compare"), permission.Compare))
	sb.WriteString(fmt.Sprintf("%s: %t\n", label("Search"), permission.Search))
	sb.WriteString(fmt.Sprintf("%s: %t\n", label("Read"), permission.Read))
	sb.WriteString(fmt.Sprintf("%s: %t\n", label("Write"), permission.Write))
	sb.WriteString("-------------------------------------------------------------\n")

	return sb.String()
}
