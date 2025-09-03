package display

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

// FormatUsersByPermissionDirect renvoie les utilisateurs avec leurs permissions sous forme de string
func DisplayUsersByPermissionDirect(permissionsUsers map[string][]string) string {
	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	// Buffer pour stocker la sortie formatée
	var sb strings.Builder

	// Ajouter le titre
	sb.WriteString(title("🔑 Users with Permission") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Utiliser un `tabwriter` pour aligner proprement les colonnes
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 8, 1, ' ', 0)

	// Ajouter les en-têtes
	fmt.Fprintf(w, "%-25s %-20s\n", header("Permission Name"), header("Users"))

	// Ajouter chaque permission et ses utilisateurs associés
	for permission, users := range permissionsUsers {
		// Afficher chaque permission et la liste des utilisateurs
		fmt.Fprintf(w, "%-25s %-20s\n", permission, fmt.Sprintf("%v", users))
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
