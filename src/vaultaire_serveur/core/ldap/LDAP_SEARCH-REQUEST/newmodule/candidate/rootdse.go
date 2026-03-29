package candidate

import (
	"strings"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
)

// RootDSEEntry implémente la réponse standard RFC 4512
type RootDSEEntry struct {
	NamingContexts          []string
	RootDomainNamingContext []string
	SupportedLDAPVersion    []string
	SupportedSASLMechanisms []string
	SupportedControl        []string
	SupportedExtension      []string
	SupportedFeatures       []string
	SubschemaSubentry       string
	VendorName              string
	VendorVersion           string
}

func (r RootDSEEntry) DN() string {
	return "" // La racine a un DN vide, c'est la règle RFC
}

func (r RootDSEEntry) ObjectClasses() []string {
	return []string{"top", "LDAProotDSE"}
}

func (r RootDSEEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	all := map[string][]string{
		"objectClass":             r.ObjectClasses(),
		"namingContexts":          r.NamingContexts,
		"rootDomainNamingContext": r.RootDomainNamingContext,
		"defaultNamingContext":    r.RootDomainNamingContext, // Souvent identique au Root
		"subschemaSubentry":       {r.SubschemaSubentry},
		"supportedLDAPVersion":    r.SupportedLDAPVersion,
		"supportedSASLMechanisms": r.SupportedSASLMechanisms,
		"supportedControl":        r.SupportedControl,
		"supportedExtension":      r.SupportedExtension,
		"supportedFeatures":       r.SupportedFeatures,
		"vendorName":              {r.VendorName},
		"vendorVersion":           {r.VendorVersion},
		"ibmdirectoryversion":     {"1.0.0"}, // Pour satisfaire la demande IBM/Tivoli
		"altServer":               {},        // Souvent attendu vide si non utilisé
	}

	result := make(map[string][]string)
	includeAll := len(requested) == 0 || contains(requested, "*")

	for k, v := range all {
		if includeAll || contains(requested, k) {
			if typesOnly {
				result[k] = []string{}
			} else {
				result[k] = v
			}
		}
	}
	return result
}
func (ou RootDSEEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := ou.GetAttributes([]string{attr}, false)
	return res[attr]
}

// NewRootDSE construit une entrée RootDSE cohérente avec les standards LDAP
func NewRootDSE() RootDSEEntry {
	// On utilise le premier domaine comme racine par défaut
	rootDomain := ldaptools.GetDefaultRootDN()

	return RootDSEEntry{
		NamingContexts:          rootDomain,
		RootDomainNamingContext: rootDomain,
		// Version LDAP v3 standard
		SupportedLDAPVersion: []string{"3"},
		// Authentification simple supportée
		SupportedSASLMechanisms: []string{"PLAIN", "SIMPLE"},
		// Contrôles standards (Pagination indispensable pour Softerra/AD)
		SupportedControl: []string{
			"1.2.840.113556.1.4.319",  // pagedResultsControl
			"2.16.840.1.113730.3.4.2", // manageDSAit
		},
		// Extensions standards
		SupportedExtension: []string{
			"1.3.6.1.4.1.1466.20037", // StartTLS
		},
		// Fonctionnalités du serveur
		SupportedFeatures: []string{
			"1.3.6.1.4.1.4203.1.5.1", // allOperationalAttributes
		},
		// Lien vers le schéma (point névralgique pour la compatibilité)
		SubschemaSubentry: "cn=schema",
		// Identité du serveur
		VendorName:    "VaultAire LDAP Server",
		VendorVersion: "1.0.0",
	}
}
