package candidate

import "strings"

type SchemaEntry struct {
	CN                string
	CreateTimestamp   []string
	ModifyTimestamp   []string
	ObjectClassDefs   []string
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
	return []string{"top", "subschema"}
}

func (s SchemaEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	// On mappe les champs de la structure vers la réponse LDAP
	all := map[string][]string{
		"objectClass":       {"top", "subschema"},
		"cn":                {s.CN},
		"objectClasses":     s.ObjectClassDefs,
		"attributeTypes":    s.AttributeTypes,
		"createTimestamp":   s.CreateTimestamp,
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

func (s SchemaEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := s.GetAttributes([]string{attr}, false)
	if vals, ok := res[attr]; ok {
		return vals
	}
	for k, v := range res {
		if strings.EqualFold(k, attr) {
			return v
		}
	}
	return nil
}

// NewSchemaEntry construit l'entrée de schéma complète.
// Elle définit les règles de validation que les clients (Nextcloud, Windows, etc.)
// utiliseront pour interroger ton annuaire.
func NewSchemaEntry() SchemaEntry {
	return SchemaEntry{
		CN: "schema",

		ObjectClassDefs: []string{
			"( 2.5.6.0 NAME 'top' ABSTRACT )",
			"( 2.5.6.0 NAME 'subschema' AUXILIARY )",
			"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )",
			"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL )",
			"( 2.5.6.10 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( member $ cn ) )",
			"( 2.5.6.30 NAME 'posixAccount' SUP top AUXILIARY )",
			"( 1.3.6.1.1.5.2 NAME 'groupOfUniqueNames' SUP top STRUCTURAL MUST ( uniqueMember $ cn ) )",
		},

		AttributeTypes: []string{
			"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
			"( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 2.5.4.4 NAME 'sn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 0.9.2342.19200300.100.1.3 NAME 'mail' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
			"( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
			"( 1.2.840.113556.1.4.8 NAME 'memberOf' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 2.5.4.31 NAME 'member' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		},

		CreateTimestamp: []string{"20260314210522Z"},
		ModifyTimestamp: []string{"20260314210522Z"},
		LdapSyntaxes: []string{
			"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
			"( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
			"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
			"( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'DN' )",
		},
		MatchingRules: []string{
			"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 2.5.13.5 NAME 'caseExactMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 1.3.6.1.1.16.3 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
			"( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		},

		MatchingRuleUse:   []string{},
		DITContentRules:   []string{},
		NameForms:         []string{},
		DITStructureRules: []string{},
	}
}
