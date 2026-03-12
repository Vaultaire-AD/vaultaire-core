package permission

import (
	"vaultaire/serveur/storage"
	"strings"
)

// MergePermissionContent fusionne deux contenus de permission (union = plus permissif).
// Utilisé pour READ = merge(can_read, api_read_permission) et WRITE = merge(can_write, api_write_permission).
func MergePermissionContent(a, b string) string {
	pa := ParsePermissionContent(strings.TrimSpace(a))
	pb := ParsePermissionContent(strings.TrimSpace(b))
	merged := mergeParsed(pa, pb)
	return parsedPermissionToString(merged)
}

func mergeParsed(a, b storage.ParsedPermission) storage.ParsedPermission {
	var out storage.ParsedPermission
	if a.All || b.All {
		out.All = true
		return out
	}
	if a.Deny && b.Deny {
		out.Deny = true
		return out
	}
	if a.Deny {
		return b
	}
	if b.Deny {
		return a
	}
	// Union des domaines (dédupliqués)
	seenNo := make(map[string]bool)
	seenWith := make(map[string]bool)
	for _, d := range a.NoPropagation {
		d = strings.TrimSpace(d)
		if d != "" {
			seenNo[d] = true
		}
	}
	for _, d := range b.NoPropagation {
		d = strings.TrimSpace(d)
		if d != "" {
			seenNo[d] = true
		}
	}
	for _, d := range a.WithPropagation {
		d = strings.TrimSpace(d)
		if d != "" {
			seenWith[d] = true
		}
	}
	for _, d := range b.WithPropagation {
		d = strings.TrimSpace(d)
		if d != "" {
			seenWith[d] = true
		}
	}
	for d := range seenNo {
		out.NoPropagation = append(out.NoPropagation, d)
	}
	for d := range seenWith {
		out.WithPropagation = append(out.WithPropagation, d)
	}
	return out
}

func parsedPermissionToString(p storage.ParsedPermission) string {
	if p.All {
		return "all"
	}
	if p.Deny && len(p.NoPropagation) == 0 && len(p.WithPropagation) == 0 {
		return "nil"
	}
	var parts []string
	if len(p.WithPropagation) > 0 {
		parts = append(parts, "(1:"+strings.Join(p.WithPropagation, ",")+")")
	}
	if len(p.NoPropagation) > 0 {
		parts = append(parts, "(0:"+strings.Join(p.NoPropagation, ",")+")")
	}
	if len(parts) == 0 {
		return "nil"
	}
	return strings.Join(parts, "")
}
