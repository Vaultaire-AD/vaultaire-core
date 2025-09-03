package display

import (
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

// DisplayAllGPOs affiche toutes les GPO dans un format lisible
func DisplayAllGPOs(gpos []*storage.LinuxGPO) string {
	if len(gpos) == 0 {
		return color.RedString("❌ Aucune GPO trouvée.")
	}

	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	// Utilisation d'un StringBuilder pour accumuler la sortie
	var sb strings.Builder

	// Ajouter le titre
	sb.WriteString(title("🔒 Liste des GPO") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 8, 1, ' ', 0)

	// Affichage des GPO
	for _, gpo := range gpos {
		fmt.Fprintf(w, "%-20s: %-30s\n", header("ID"), fmt.Sprintf("%d", gpo.ID))
		fmt.Fprintf(w, "%-20s: %-30s\n", header("Nom de la GPO"), gpo.GPOName)
		fmt.Fprintf(w, "%-20s: %-30s\n", header("Ubuntu Commande"), gpo.Ubuntu)
		fmt.Fprintf(w, "%-20s: %-30s\n", header("Debian Commande"), gpo.Debian)
		fmt.Fprintf(w, "%-20s: %-30s\n", header("Rocky Commande"), gpo.Rocky)
		sb.WriteString(b.String())
		b.Reset()
	}

	// Ajouter la ligne de séparation
	sb.WriteString("--------------------------------------------------\n")

	// Retourner la chaîne accumulée
	return sb.String()
}
