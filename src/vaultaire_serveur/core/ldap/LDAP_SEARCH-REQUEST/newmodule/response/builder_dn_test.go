package response

import (
	"strings"
	"testing"

	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
)

// TO-DO 221 : le DN part dans ObjectName, jamais aussi comme attribut « dn »,
// qu'on demande tout, rien, ou « dn » nommément.
func TestLeDNNEstPasUnAttribut(t *testing.T) {
	ou := candidate.OUEntry{Name: "users", BaseDN: "acme.lan"}
	for _, demandes := range [][]string{nil, {"*"}, {"dn"}, {"dn", "ou"}} {
		e := BuildLDAPEntryForSend(ou, demandes, false)
		if e.ObjectName != ou.DN() {
			t.Fatalf("%v : ObjectName = %q", demandes, e.ObjectName)
		}
		for _, a := range e.Attributes {
			if strings.EqualFold(a.Type, "dn") {
				t.Fatalf("%v : attribut « dn » renvoyé (%v)", demandes, a.Vals)
			}
		}
	}
}
