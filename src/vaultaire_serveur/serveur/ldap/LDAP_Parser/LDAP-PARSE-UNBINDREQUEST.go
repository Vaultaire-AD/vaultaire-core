package ldapparser

import ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"

func parseUnBindRequest() (ldapstorage.LDAPProtocolOperation, error) {
	// L'UnbindRequest est toujours vide, on retourne juste une instance.
	return ldapstorage.UnbindRequest{}, nil
}
