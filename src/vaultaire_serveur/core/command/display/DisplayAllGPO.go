package display

import (
	"fmt"
	"strings"

	dbgpo "vaultaire/core/database/db_gpo"

	"github.com/fatih/color"
)

// DisplayAllGPOs affiche la liste des GPO : scope, version, activation, nombre
// de modules et groupes liés. Le détail des paramètres n'est pas montré ici,
// c'est le rôle de DisplayGPOByName.
func DisplayAllGPOs(policies []dbgpo.PolicySummary) string {
	if len(policies) == 0 {
		return color.RedString("❌ Aucune GPO trouvée.")
	}

	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()
	dim := color.New(color.FgHiBlack).SprintFunc()

	var sb strings.Builder
	sb.WriteString(title("🔒 Liste des GPO") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	for _, p := range policies {
		state := color.GreenString("activée")
		if !p.Enabled {
			state = color.RedString("désactivée")
		}
		groups := "aucun groupe"
		if len(p.Groups) > 0 {
			groups = strings.Join(p.Groups, ", ")
		}

		sb.WriteString(fmt.Sprintf("%-16s: %s\n", header("Nom"), p.Name))
		sb.WriteString(fmt.Sprintf("%-16s: %s\n", header("Scope"), p.Scope))
		sb.WriteString(fmt.Sprintf("%-16s: v%d (%s)\n", header("Version"), p.Version, state))
		sb.WriteString(fmt.Sprintf("%-16s: %d\n", header("Modules"), p.ModuleCount))
		sb.WriteString(fmt.Sprintf("%-16s: %s\n", header("Groupes"), groups))
		if p.Description != "" {
			sb.WriteString(fmt.Sprintf("%-16s: %s\n", header("Description"), p.Description))
		}
		sb.WriteString(dim("  id "+fmt.Sprint(p.ID)) + "\n")
		sb.WriteString("--------------------------------------------------\n")
	}
	return sb.String()
}
