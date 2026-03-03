package newmodule

import (
	"vaultaire/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/ldap_types"
	"vaultaire/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/response"
	"net"
)

func SendRootDSE(conn net.Conn, messageID int) {
	entry := ldap_types.SearchResultEntry{
		ObjectName: "",
		Attributes: []ldap_types.PartialAttribute{
			{
				Type: "objectClass",
				Vals: []string{"top"},
			},
			{
				Type: "namingContexts",
				Vals: []string{"dc=vaultaire,dc=local"},
			},
			{
				Type: "supportedLDAPVersion",
				Vals: []string{"3"},
			},
			{
				Type: "supportedSASLMechanisms",
				Vals: []string{"SIMPLE"},
			},
			{
				Type: "vendorName",
				Vals: []string{"Vaultaire LDAP"},
			},
			{
				Type: "vendorVersion",
				Vals: []string{"0.1"},
			},
		},
	}

	response.SendLDAPSearchResultEntry(conn, messageID, entry)
	response.SendLDAPSearchResultDone(conn, messageID)
}
