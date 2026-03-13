package newmodule

import (
	"database/sql"
	"fmt"
	"net"
	"vaultaire/core/domain"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/ldap_types"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/response"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/security"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	"vaultaire/core/logs"
)

type RootDSE struct {
	NamingContexts          []string
	RootDomainNamingContext []string
	SupportedLDAPVersion    []string
	SupportedSASLMechanisms []string
	SupportedControl        []string
	SupportedExtension      []string
	ForestFunctionality     []string
	DomainFunctionality     []string
	DSAName                 []string
	VendorName              string
	VendorVersion           string
}

func SendRootDSE(conn net.Conn, messageID int, db *sql.DB, session *ldapsessionmanager.LDAPSession) {
	// 1. Log clair pour savoir que cette fonction est bien déclenchée
	logs.Write_Log("DEBUG", fmt.Sprintf("Triggering SendRootDSE for user: %s", session.Username))

	// 2. Récupérer les domaines depuis la base
	allDomains, err := domain.GetAllGroupDomains(db, true)
	if err != nil {
		logs.Write_Log("ERROR", "RootDSE: Failed to get domains: "+err.Error())
		response.SendLDAPSearchFailure(conn, messageID, "Internal Error")
		return
	}

	// 3. Filtrer les domaines selon les permissions de l'utilisateur
	var authorizedDomains []string
	for _, d := range allDomains {
		if security.IsAuthorizedToSearch(session.Username, d) {
			authorizedDomains = append(authorizedDomains, d)
		}
	}

	// 4. Construire la réponse RootDSE
	info := GetRootDSE_WithDomains(authorizedDomains)

	attrs := []ldap_types.PartialAttribute{
		{Type: "objectClass", Vals: []string{"top", "LDAProotDSE"}},
		{Type: "namingContexts", Vals: info.NamingContexts},
		{Type: "rootDomainNamingContext", Vals: info.RootDomainNamingContext},
		{Type: "supportedLDAPVersion", Vals: info.SupportedLDAPVersion},
		{Type: "supportedSASLMechanisms", Vals: info.SupportedSASLMechanisms},
		{Type: "supportedControl", Vals: info.SupportedControl},
		{Type: "supportedExtension", Vals: info.SupportedExtension},
		{Type: "forestFunctionality", Vals: info.ForestFunctionality},
		{Type: "domainFunctionality", Vals: info.DomainFunctionality},
		{Type: "dsaName", Vals: info.DSAName},
		{Type: "vendorName", Vals: []string{info.VendorName}},
		{Type: "vendorVersion", Vals: []string{info.VendorVersion}},
	}

	entry := ldap_types.SearchResultEntry{
		ObjectName: "", // DN vide pour la racine
		Attributes: attrs,
	}

	// 5. Envoi au client
	response.SendLDAPSearchResultEntry(conn, messageID, entry)
	response.SendLDAPSearchResultDone(conn, messageID)

	logs.Write_Log("DEBUG", fmt.Sprintf("RootDSE sent successfully to %s with %d namingContexts",
		session.Username, len(authorizedDomains)))
}

// Helper pour préparer la structure
func GetRootDSE_WithDomains(authorizedDomains []string) RootDSE {
	return RootDSE{
		NamingContexts: authorizedDomains,
		// Si tu as un domaine racine, mets-le ici, sinon le premier autorisé
		RootDomainNamingContext: []string{authorizedDomains[0]},
		SupportedLDAPVersion:    []string{"3"},
		SupportedSASLMechanisms: []string{"PLAIN", "SIMPLE"},
		// Ces OIDs correspondent aux standards AD pour le support des contrôles/extensions
		SupportedControl:    []string{"1.2.840.113556.1.4.319", "1.2.840.113556.1.4.801"},
		SupportedExtension:  []string{"1.3.6.1.4.1.1466.20037"},
		ForestFunctionality: []string{"7"}, // Correspond au niveau Windows Server 2016
		DomainFunctionality: []string{"7"},
		DSAName:             []string{"CN=NTDS Settings,CN=VaultAire,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration," + authorizedDomains[0]},
		VendorName:          "VaultAire LDAP Server",
		VendorVersion:       "1.0.0",
	}
}
