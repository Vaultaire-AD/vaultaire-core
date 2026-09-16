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

	// Le titre est rendu par la Fiche ci-dessous ; seuls les intertitres et le
	// texte atténué restent à la charge de cette fonction.
	section := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	dim := color.New(color.FgHiBlack).SprintFunc()

	// L'en-tête passe par Fiche : les `%-16s` appliqués à des libellés colorés
	// comptaient les codes ANSI dans la largeur, et décalaient donc toutes les
	// valeurs de treize caractères. Voir table.go.
	f := NouvelleFiche("GPO — " + policy.Name)
	f.Ajouter("Identifiant", fmt.Sprint(policy.ID))
	f.Ajouter("Portée", scopeLabel(policy.Scope))
	f.Ajouter("Version", fmt.Sprintf("v%d", policy.Version))
	f.Ajouter("État", etatGPO(policy.Enabled))
	// Le mode de dérive se réglait en ligne de commande et ne se relisait qu'en
	// web : un réglage qu'on pose sans pouvoir le vérifier là où on l'a posé.
	//
	// La phrase dit l'EFFET et pas seulement la valeur. « audit » seul ne dit
	// pas qu'une machine restera durablement dérivée — c'est pourtant toute la
	// portée du réglage.
	f.Ajouter("Dérive", modeDeriveLisible(policy.EffectiveDriftMode()))
	f.Ajouter("Description", policy.Description)
	if hash, err := gpo.PolicyHash(*policy); err == nil && len(hash) >= 16 {
		f.Ajouter("Empreinte", hash[:16]+"…")
	}

	var sb strings.Builder
	sb.WriteString(f.String())

	sb.WriteString("\n" + section("Groupes liés") + "\n")
	if len(policy.Groups) == 0 {
		// Une GPO sans groupe ne s'applique à personne. Le dire, plutôt que
		// d'afficher une section vide qu'on prendrait pour un défaut.
		sb.WriteString("   aucun — cette GPO ne s'applique à personne\n")
	} else {
		for _, g := range policy.Groups {
			sb.WriteString("   - " + g + "\n")
		}
	}

	sb.WriteString("\n" + section(fmt.Sprintf("Modules (%d, dans l'ordre d'application)", len(policy.Modules))) + "\n")
	if len(policy.Modules) == 0 {
		sb.WriteString("   aucun — cette GPO est sans effet\n")
	}
	for i, m := range policy.Modules {
		schema, known := gpo.SchemaFor(m.Type)
		label := m.Type
		if known {
			label = schema.Label
		}
		sb.WriteString(fmt.Sprintf("\n   %d. %s %s\n", i+1, label,
			dim("("+m.Type+", ordre "+fmt.Sprint(m.ApplyOrder)+", id "+fmt.Sprint(m.ID)+")")))

		for _, line := range formatModuleParams(schema, known, m.Params) {
			sb.WriteString("      " + line + "\n")
		}
	}

	return sb.String()
}

// formatModuleParams rend les paramètres d'un module, dans l'ordre du schéma
// quand celui-ci est connu, par ordre alphabétique sinon.
func formatModuleParams(schema gpo.ModuleSchema, known bool, params map[string]string) []string {
	// Deux passes : la première relève les couples à afficher, la seconde les
	// aligne sur le libellé le plus long.
	//
	// `%-24s` supposait qu'aucun libellé ne dépasse vingt-quatre caractères.
	// Le premier qui dépasse pousse sa ligne, et le paramètre paraît alors
	// appartenir au module suivant.
	type couple struct{ label, valeur string }
	var couples []couple

	emit := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		couples = append(couples, couple{label, value})
	}

	if known {
		for _, f := range schema.Fields {
			emit(f.Label, params[f.Name])
		}
	} else {
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			emit(k, params[k])
		}
	}

	largeur := 0
	for _, c := range couples {
		if l := LargeurVisible(c.label); l > largeur {
			largeur = l
		}
	}

	var lines []string
	for _, c := range couples {
		if strings.Contains(c.valeur, "\n") {
			// Valeur multiligne — un script, un fichier de configuration. Elle
			// est repliée sous son libellé plutôt qu'écrasée sur une ligne.
			lines = append(lines, remplir(c.label, LargeurVisible(c.label), largeur)+" :")
			for _, l := range strings.Split(c.valeur, "\n") {
				lines = append(lines, "    │ "+l)
			}
			continue
		}
		lines = append(lines, remplir(c.label, LargeurVisible(c.label), largeur)+" : "+c.valeur)
	}
	return lines
}

// scopeLabel traduit un scope pour l'affichage.
// modeDeriveLisible dit ce que le mode fait, pas seulement son nom.
//
// « audit » seul se lit comme une nuance de réglage. Ce qu'il veut dire, c'est
// que les machines visées resteront dérivées jusqu'à un retour en enforce — et
// c'est cela qu'on veut voir en ouvrant la fiche.
func modeDeriveLisible(m gpo.DriftMode) string {
	if m == gpo.DriftAudit {
		return "audit — les écarts sont signalés, JAMAIS corrigés"
	}
	return "enforce — les écarts sont corrigés au cycle suivant"
}

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
