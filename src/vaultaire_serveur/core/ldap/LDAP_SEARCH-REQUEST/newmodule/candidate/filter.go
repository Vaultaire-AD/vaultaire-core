package candidate

import (
	"fmt"
	"strings"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/filter"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Filtre applique un filtre LDAP logique (LDAPFilter) à une liste d’entrées
func Filtre(entries []ldapinterface.LDAPEntry, f *ldapstorage.LDAPFilter, baseDN string, scope int) []ldapinterface.LDAPEntry {

	if f == nil {
		logs.Write_Log("DEBUG", "Filtre LDAP nil, toutes les entrées sont retournées")
		return entries
	}

	logs.Write_Log("DEBUG", fmt.Sprintf(
		"Application du filtre LDAP sur %d entrées (Type=%v)",
		len(entries),
		f.Type,
	))
	var result []ldapinterface.LDAPEntry
	if len(entries) == 0 {
		logs.Write_Log("DEBUG", "Aucune entrée candidate: résultat de filtre vide")
		return result
	}

	// Le filtre contient les NOMS D'UTILISATEUR recherchés.
	//
	// Il partait sur la sortie standard à CHAQUE recherche, sans horodatage,
	// sans niveau et sans rotation — donc hors du système de journalisation et
	// de ses protections, mais bien dans les journaux Docker.
	//
	// Passé en DEBUG : muet en exploitation, et soumis au même traitement que
	// le reste quand on l'active.
	if storage.Debug {
		logs.Write_Log("DEBUG", "ldap: filtre appliqué à "+entries[0].DN()+" :\n"+DumpFilter(f, 0))
	}

	for _, e := range entries {
		logs.Write_Log("DEBUG", fmt.Sprintf("Vérification de %s : classes=%v", e.DN(), e.GetAttribute("objectClass")))
		if filter.Evaluate(e, f, baseDN, scope) {
			result = append(result, e)
			logs.Write_Log("DEBUG", fmt.Sprintf(
				"Entrée %s correspond au filtre",
				e.DN(),
			))
		} else {
			logs.Write_Log("DEBUG", fmt.Sprintf(
				"Entrée %s ne correspond PAS au filtre",
				e.DN(),
			))
		}
	}

	logs.Write_Log("DEBUG", fmt.Sprintf(
		"Filtre LDAP appliqué : %d/%d entrées correspondent",
		len(result),
		len(entries),
	))

	return result
}

// DumpFilter affiche la structure récursive du filtre LDAP pour le debug
func DumpFilter(f *ldapstorage.LDAPFilter, indent int) string {
	if f == nil {
		return "nil"
	}

	var sb strings.Builder
	padding := strings.Repeat("  ", indent)

	switch f.Type {
	case ldapstorage.FilterAnd:
		sb.WriteString(fmt.Sprintf("%s(&)\n", padding))
	case ldapstorage.FilterOr:
		sb.WriteString(fmt.Sprintf("%s(|)\n", padding))
	case ldapstorage.FilterNot:
		sb.WriteString(fmt.Sprintf("%s(!)\n", padding))
	case ldapstorage.FilterEquality:
		sb.WriteString(fmt.Sprintf("%s(%s=%s)\n", padding, f.Attribute, f.Value))
	case ldapstorage.FilterPresent:
		sb.WriteString(fmt.Sprintf("%s(%s=*)\n", padding, f.Attribute))
	case ldapstorage.FilterSubstring:
		sb.WriteString(fmt.Sprintf("%s(%s=*%s*)\n", padding, f.Attribute, f.Value))
	case ldapstorage.FilterExtensible:
		sb.WriteString(fmt.Sprintf("%s(%s:dn:=%s)\n", padding, f.Attribute, f.Value))
	case ldapstorage.FilterGreaterOrEqual:
		sb.WriteString(fmt.Sprintf("%s(%s>=%s)\n", padding, f.Attribute, f.Value))
	case ldapstorage.FilterLessOrEqual:
		sb.WriteString(fmt.Sprintf("%s(%s<=%s)\n", padding, f.Attribute, f.Value))
	case ldapstorage.FilterApprox:
		sb.WriteString(fmt.Sprintf("%s(%s~=%s)\n", padding, f.Attribute, f.Value))
	default:
		sb.WriteString(fmt.Sprintf("%s(UnknownType:%d %s=%s)\n", padding, f.Type, f.Attribute, f.Value))
	}

	// Appel récursif pour les sous-filtres
	for _, sub := range f.SubFilters {
		sb.WriteString(DumpFilter(sub, indent+1))
	}

	return sb.String()
}
