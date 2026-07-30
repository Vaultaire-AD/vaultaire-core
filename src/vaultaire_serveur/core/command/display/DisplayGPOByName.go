package display

import (
	"fmt"
	"sort"
	"strings"

	"vaultaire/core/gpo"

	"github.com/fatih/color"
)

// DisplayGPOByName affiche le détail d'une GPO : métadonnées, groupes liés, puis
// chaque module dans son ordre d'application réel avec ses paramètres.
//
// Les modules sont affichés avec le libellé du catalogue plutôt que leur type
// technique, et les champs dans l'ordre du schéma : ce qui est lu correspond
// ainsi exactement à ce que l'agent client appliquera, et dans le même ordre.
func DisplayGPOByName(policy *gpo.Policy) string {
	if policy == nil {
		return color.RedString("❌ Aucune GPO trouvée.")
	}

	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()
	section := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	dim := color.New(color.FgHiBlack).SprintFunc()

	var sb strings.Builder
	sb.WriteString(title("🔒 GPO "+policy.Name) + "\n")
	sb.WriteString("--------------------------------------------------\n")

	state := color.GreenString("activée")
	if !policy.Enabled {
		state = color.RedString("désactivée")
	}
	sb.WriteString(fmt.Sprintf("%-16s: %d\n", header("ID"), policy.ID))
	sb.WriteString(fmt.Sprintf("%-16s: %s\n", header("Scope"), scopeLabel(policy.Scope)))
	sb.WriteString(fmt.Sprintf("%-16s: v%d (%s)\n", header("Version"), policy.Version, state))
	if policy.Description != "" {
		sb.WriteString(fmt.Sprintf("%-16s: %s\n", header("Description"), policy.Description))
	}
	if hash, err := gpo.PolicyHash(*policy); err == nil && len(hash) >= 16 {
		sb.WriteString(fmt.Sprintf("%-16s: %s\n", header("Empreinte"), dim(hash[:16]+"…")))
	}

	sb.WriteString("\n" + section("Groupes liés") + "\n")
	if len(policy.Groups) == 0 {
		sb.WriteString("   ❌ Aucun groupe — cette GPO ne s'applique à personne.\n")
	} else {
		for _, g := range policy.Groups {
			sb.WriteString("   - " + g + "\n")
		}
	}

	sb.WriteString("\n" + section(fmt.Sprintf("Modules (%d, dans l'ordre d'application)", len(policy.Modules))) + "\n")
	if len(policy.Modules) == 0 {
		sb.WriteString("   ❌ Aucun module — cette GPO est sans effet.\n")
	}
	for i, m := range policy.Modules {
		schema, known := gpo.SchemaFor(m.Type)
		label := m.Type
		if known {
			label = schema.Label
		}
		sb.WriteString(fmt.Sprintf("\n   %d. %s %s\n", i+1, header(label),
			dim("("+m.Type+", ordre "+fmt.Sprint(m.ApplyOrder)+", id "+fmt.Sprint(m.ID)+")")))

		for _, line := range formatModuleParams(schema, known, m.Params) {
			sb.WriteString("      " + line + "\n")
		}
	}

	sb.WriteString("--------------------------------------------------\n")
	return sb.String()
}

// formatModuleParams rend les paramètres d'un module, dans l'ordre du schéma
// quand celui-ci est connu, par ordre alphabétique sinon.
func formatModuleParams(schema gpo.ModuleSchema, known bool, params map[string]string) []string {
	var lines []string
	emit := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		if strings.Contains(value, "\n") {
			lines = append(lines, fmt.Sprintf("%-24s:", label))
			for _, l := range strings.Split(value, "\n") {
				lines = append(lines, "    │ "+l)
			}
			return
		}
		lines = append(lines, fmt.Sprintf("%-24s: %s", label, value))
	}

	if known {
		for _, f := range schema.Fields {
			emit(f.Label, params[f.Name])
		}
		return lines
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		emit(k, params[k])
	}
	return lines
}

// scopeLabel traduit un scope pour l'affichage.
func scopeLabel(s gpo.Scope) string {
	switch s {
	case gpo.ScopeMachine:
		return "machine (appliquée à l'ordinateur, au démarrage et par rafraîchissement)"
	case gpo.ScopeUser:
		return "user (appliquée après authentification, à l'utilisateur)"
	default:
		return string(s)
	}
}
