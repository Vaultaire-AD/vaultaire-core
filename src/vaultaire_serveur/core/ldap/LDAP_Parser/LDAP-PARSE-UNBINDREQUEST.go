package ldapparser

import ldapstorage "vaultaire/core/ldap/LDAP_Storage"

func parseUnBindRequest() (ldapstorage.LDAPProtocolOperation, error) {
	// L'UnbindRequest est toujours vide, on retourne juste une instance.
	return ldapstorage.UnbindRequest{}, nil
}
