package display

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"vaultaire/core/storage"

	"github.com/fatih/color"
)

// FormatSoftware renvoie les informations du client (logiciel) sous forme de chaîne formatée
func DisplaySoftware(software *storage.Software) string {
	if software == nil {
		return color.RedString("❌ Aucun client trouvé.")
	}

	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()
	booleanStyle := func(value bool) string {
		if value {
			return color.GreenString("✅ Yes")
		}
		return color.RedString("❌ No")
	}

	// Utilisation d'un StringBuilder pour accumuler la sortie
	var sb strings.Builder

	// Ajouter le titre
	sb.WriteString(title("💻 Client Information") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 8, 1, ' ', 0)

	// Ajouter les informations du client
	fmt.Fprintf(w, "%-20s: %-30s\n", header("ID"), fmt.Sprintf("%d", software.ID))
	fmt.Fprintf(w, "%-20s: %-30s\n", header("Type"), software.LogicielType)
	fmt.Fprintf(w, "%-20s: %-30s\n", header("Computeur ID"), software.ComputeurID)
	fmt.Fprintf(w, "%-20s: %-30s\n", header("Hostname"), software.Hostname)
	fmt.Fprintf(w, "%-20s: %-30s\n", header("Serveur"), booleanStyle(software.Serveur))
	fmt.Fprintf(w, "%-20s: %-30d\n", header("Processeur"), software.Processeur)
	fmt.Fprintf(w, "%-20s: %-30s\n", header("RAM"), software.RAM)
	fmt.Fprintf(w, "%-20s: %-30s\n", header("OS"), software.OS)

	// Afficher les groupes et permissions associés
	groups := "Aucun"
	if len(software.Groups) > 0 && software.Groups[0] != "" {
		groups = strings.Join(software.Groups, ", ")
	}

	permissions := "Aucune"
	if len(software.Permissions) > 0 && software.Permissions[0] != "" {
		permissions = strings.Join(software.Permissions, ", ")
	}

	fmt.Fprintf(w, "%-20s: %-30s\n", header("Groupes"), groups)
	fmt.Fprintf(w, "%-20s: %-30s\n", header("Permissions"), permissions)

	// Vider le tampon et ajouter au StringBuilder
	err := w.Flush()
	if err != nil {
		return "Error flushing writer: " + err.Error()
	}
	sb.WriteString(b.String())

	// Ajouter la ligne de séparation
	sb.WriteString("--------------------------------------------------\n")

	// Retourner la chaîne accumulée
	return sb.String()
}
