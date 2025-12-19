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
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("description"), permission.Description))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("none"), permission.None))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("auth"), permission.Auth))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("compare"), permission.Compare))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("search"), permission.Search))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("can_read"), permission.Read))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("can_write"), permission.Write))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("api_read_permission"), permission.APIRead))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("api_write_permission"), permission.APIWrite))
	sb.WriteString(fmt.Sprintf("%s: %s\n", label("web_admin"), permission.Web_admin))
	sb.WriteString("-------------------------------------------------------------\n")

	return sb.String()
}
