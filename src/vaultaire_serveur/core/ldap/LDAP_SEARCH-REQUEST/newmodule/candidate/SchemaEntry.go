package candidate

import "strings"

type SchemaEntry struct {
	CN                string
	ModifyTimestamp   []string
	LdapSyntaxes      []string
	AttributeTypes    []string
	MatchingRules     []string
	MatchingRuleUse   []string
	DITContentRules   []string
	NameForms         []string
	DITStructureRules []string
}

func (s SchemaEntry) DN() string {
	return "cn=schema"
}

func (s SchemaEntry) ObjectClasses() []string {
	return []string{"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		"( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou )",
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )",
		"( 1.2.840.113556.1.5.8 NAME 'user' SUP person STRUCTURAL )",
		"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP person STRUCTURAL )",
		"( 1.2.840.113556.1.5.9 NAME 'group' SUP top STRUCTURAL )"}
}

func (s SchemaEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	// On mappe les champs de la structure vers la réponse LDAP
	all := map[string][]string{
		"objectClass":       {"top", "subschema"},
		"cn":                {s.CN},
		"attributeTypes":    s.AttributeTypes,
		"modifyTimestamp":   s.ModifyTimestamp,
		"ldapSyntaxes":      s.LdapSyntaxes,
		"matchingRules":     s.MatchingRules,
		"matchingRuleUse":   s.MatchingRuleUse,
		"dITContentRules":   s.DITContentRules,
		"nameForms":         s.NameForms,
		"dITStructureRules": s.DITStructureRules,
	}

	// Filtrage sélectif
	if len(requested) == 0 || (len(requested) == 1 && requested[0] == "*") {
		return all
	}

	filtered := make(map[string][]string)
	for _, attr := range requested {
		key := strings.ToLower(attr)
		// Recherche insensible à la casse
		for k, v := range all {
			if strings.ToLower(k) == key {
				filtered[k] = v
			}
		}
	}
	return filtered
}

func (ou SchemaEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := ou.GetAttributes([]string{attr}, false)
	return res[attr]
}

// NewSchemaEntry construit l'entrée de schéma complète.
// Elle définit les règles de validation que les clients (Nextcloud, Windows, etc.)
// utiliseront pour interroger ton annuaire.
func NewSchemaEntry() SchemaEntry {
	return SchemaEntry{
		CN: "schema",

		// 1. Définition des types d'attributs (Syntaxe de validation)
		AttributeTypes: []string{
			"( 2.5.4.0 NAME 'objectClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
			"( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 2.5.4.4 NAME 'sn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 0.9.2342.19200300.100.1.3 NAME 'mail' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
			"( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
			"( 1.2.840.113556.1.4.8 NAME 'memberOf' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		},

		// 3. Métadonnées opérationnelles
		ModifyTimestamp: []string{"20260314210522Z"},
		LdapSyntaxes:    []string{"1.3.6.1.4.1.1466.115.121.1.15"},
		MatchingRules:   []string{"2.5.13.0"}, // CaseIgnoreMatch

		// Champs optionnels mais attendus vides si non utilisés
		MatchingRuleUse:   []string{},
		DITContentRules:   []string{},
		NameForms:         []string{},
		DITStructureRules: []string{},
	}
}
