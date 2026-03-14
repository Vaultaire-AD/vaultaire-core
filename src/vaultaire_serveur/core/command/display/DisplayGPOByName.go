package display

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"vaultaire/core/storage"

	"github.com/fatih/color"
)

// DisplayGPOInfo affiche les informations détaillées d'une GPO
func DisplayGPOByName(gpo *storage.LinuxGPO) string {
	if gpo == nil {
		return color.RedString("❌ Aucune GPO trouvée.")
	}

	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	// Utilisation d'un StringBuilder pour accumuler la sortie
	var sb strings.Builder

	// Ajouter le titre
	sb.WriteString(title("🔒 GPO Information") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 8, 1, ' ', 0)

	// Ajouter les informations de la GPO
	fmt.Fprintf(w, "%-20s: %-30s\n", header("ID"), fmt.Sprintf("%d", gpo.ID))
	fmt.Fprintf(w, "%-20s: %-30s\n", header("Nom de la GPO"), gpo.GPOName)
	fmt.Fprintf(w, "%-20s: %-30s\n", header("Ubuntu Commande"), gpo.Ubuntu)
	fmt.Fprintf(w, "%-20s: %-30s\n", header("Debian Commande"), gpo.Debian)
	fmt.Fprintf(w, "%-20s: %-30s\n", header("Rocky Commande"), gpo.Rocky)

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
