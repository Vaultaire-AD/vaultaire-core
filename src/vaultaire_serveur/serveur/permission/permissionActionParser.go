package permission

import (
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
)

// FormatPermissionAction transforme une PermissionAction en string lisible
func FormatPermissionAction(pa storage.PermissionAction) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Type: %s\n", pa.Type))

	if pa.Type == "custom" {
		if len(pa.WithPropagation) > 0 {
			sb.WriteString("  🌍 Avec propagation:\n")
			for _, d := range pa.WithPropagation {
				sb.WriteString(fmt.Sprintf("    - %s\n", d))
			}
		}

		if len(pa.WithoutPropagation) > 0 {
			sb.WriteString("  🏷️ Sans propagation:\n")
			for _, d := range pa.WithoutPropagation {
				sb.WriteString(fmt.Sprintf("    - %s\n", d))
			}
		}
	}

	return sb.String()
}

func ParsePermissionAction(value string) storage.PermissionAction {
	value = strings.TrimSpace(value)

	// Cas nil
	if value == "" || value == "nil" {
		return storage.PermissionAction{Type: "nil"}
	}

	// Cas all
	if value == "all" {
		return storage.PermissionAction{Type: "all"}
	}

	// Cas custom
	action := storage.PermissionAction{Type: "custom"}

	// Exemple: (1:infra.company.fr,it.company.fr)(0:finance.company.fr)
	parts := strings.Split(value, ")(")

	for _, p := range parts {
		// Nettoyage des parenthèses
		p = strings.TrimPrefix(p, "(")
		p = strings.TrimSuffix(p, ")")
		if p == "" {
			continue
		}

		// Split "1:infra.company.fr,it.company.fr"
		subparts := strings.SplitN(p, ":", 2)
		if len(subparts) != 2 {
			continue
		}

		propagate := subparts[0] == "1"
		domains := strings.Split(subparts[1], ",")

		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if propagate {
				action.WithPropagation = append(action.WithPropagation, d)
			} else {
				action.WithoutPropagation = append(action.WithoutPropagation, d)
			}
		}
	}

	return action
}
