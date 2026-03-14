package display

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"vaultaire/core/storage"

	"github.com/fatih/color"
)

// FormatUserInfo renvoie les infos d'un utilisateur sous forme de string
func DisplayUsersInfoByName(user *storage.GetUserInfoSingle) string {
	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()
	info := color.New(color.FgCyan).SprintFunc()
	connected := color.New(color.FgGreen).SprintFunc()
	disconnected := color.New(color.FgRed).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()

	// Buffer pour stocker la sortie formatée
	var sb strings.Builder

	// Ajouter le titre
	sb.WriteString(title("👤 User Information") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Utiliser un tabwriter pour formater les colonnes
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 8, 1, ' ', 0)

	// Définir le statut
	status := disconnected("❌ Offline")
	if user.Connected {
		status = connected("✅ Online")
	}

	// Ajouter les informations principales
	fmt.Fprintf(w, "%-20s %-20s\n", header("Username:"), info(user.Username))
	fmt.Fprintf(w, "%-20s %-20s\n", header("Firstname:"), info(user.Firstname))
	fmt.Fprintf(w, "%-20s %-20s\n", header("Lastname:"), info(user.Lastname))
	fmt.Fprintf(w, "%-20s %-20s\n", header("Email:"), info(user.Email))
	fmt.Fprintf(w, "%-20s %-20s\n", header("Date of Birth:"), info(user.DateOfBirth))
	fmt.Fprintf(w, "%-20s %-20s\n", header("Status:"), status)

	// Ajouter les groupes et permissions
	fmt.Fprintf(w, "\n%-20s %s\n", header("Groups:"), formatList(user.Groups, magenta))

	// Écrire le contenu formaté dans `sb`
	err := w.Flush()
	if err != nil {
		return "Error flushing writer: " + err.Error()
	}
	sb.WriteString(b.String())

	sb.WriteString("--------------------------------------------------\n")

	return sb.String()
}

// formatList transforme une slice en une chaîne formatée
func formatList(items []string, colorFunc func(a ...interface{}) string) string {
	if len(items) == 0 {
		return "None"
	}
	return colorFunc(fmt.Sprintf("%v", items))
}
