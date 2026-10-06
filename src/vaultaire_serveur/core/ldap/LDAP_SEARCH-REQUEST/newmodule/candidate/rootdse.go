package candidate

import (
	"strings"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
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

// Domaines — voir ldapinterface.LDAPEntry.
//
// Le RootDSE n'appartient à AUCUN domaine : c'est la racine, hors de
// l'arborescence. La chaîne vide vaut donc « écartée par le filtre
// d'autorisation », et c'est le bon comportement — cette entrée est servie par
// le chemin qui court-circuite le filtre, parce qu'elle doit rester lisible sans
// authentification (RFC 4512).
func (r RootDSEEntry) Domaines() []string {
	return nil
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

// NewRootDSE construit une entrée RootDSE cohérente avec les standards LDAP
func NewRootDSE() RootDSEEntry {
	// On utilise le premier domaine comme racine par défaut
	rootDomain := ldaptools.GetDefaultRootDN()

	return RootDSEEntry{
		NamingContexts:          rootDomain,
		RootDomainNamingContext: rootDomain,
		// Version LDAP v3 standard
		SupportedLDAPVersion: []string{"3"},

		// AUCUN mécanisme SASL.
		//
		// Le serveur ne gère que le bind SIMPLE. La liste annonçait « PLAIN » et
		// « SIMPLE » : le premier suppose un bind SASL que le parseur ne sait pas
		// lire, le second n'est pas un mécanisme SASL du tout. Un client qui les
		// croyait envoyait un bind [3] dont le contenu DER était interprété comme
		// un mot de passe, et recevait « invalid credentials » sans explication.
		//
		// Une liste vide est un attribut LDAP parfaitement valide : elle dit
		// « aucun », ce qui est vrai.
		SupportedSASLMechanisms: []string{},

		// Les contrôles : ce que le dispatcheur traite, et RIEN d'autre.
		//
		// La liste est ldapstorage.ControlesGeres, celle-là même que le
		// dispatcheur consulte pour refuser un contrôle critique : annonce et
		// traitement ne peuvent plus se contredire.
		//
		// Elles l'ont fait. La pagination (1.2.840.113556.1.4.319) était annoncée
		// alors que les contrôles reçus étaient analysés puis IGNORÉS : le serveur
		// renvoyait le jeu complet sans cookie, et un client qui pagine —
		// Softerra, les outils AD — bouclait sur la même page. Elle a été retirée
		// de l'annonce, puis implémentée (point 130), et c'est seulement là qu'elle
		// y est revenue.
		SupportedControl: append([]string(nil), ldapstorage.ControlesGeres...),

		// AUCUNE extension.
		//
		// StartTLS (1.3.6.1.4.1.1466.20037) était annoncé sans être implémenté, et
		// c'est un risque et pas seulement une gêne : un client configuré
		// « StartTLS obligatoire » voit l'extension, tente la promotion, échoue —
		// et selon son implémentation peut poursuivre EN CLAIR avec les
		// identifiants. Pour du chiffrement, LDAPS sur 636.
		//
		// WHOAMI (1.3.6.1.4.1.4203.1.11.3) est bien implémenté mais n'est pas
		// annoncé : il demande une authentification, donc un client qui l'utilise
		// est déjà lié et n'a pas eu besoin du RootDSE pour le découvrir.
		// L'annoncer à un anonyme ne lui apprendrait que la surface d'attaque.
		SupportedExtension: []string{},

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
