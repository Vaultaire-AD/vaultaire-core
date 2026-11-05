package ldaptools

import "testing"

func TestAttendusDeclares(t *testing.T) {
	set := AttendusDeclares([]string{"LDAP.acme.lan", " ", "ldap.acme.lan", "10.0.0.5"}, []string{"10.0.0.6", "vaultaire.svc"})
	if len(set.DNSNames) != 2 || set.DNSNames[0] != "ldap.acme.lan" || set.DNSNames[1] != "vaultaire.svc" {
		t.Fatalf("noms : %v", set.DNSNames)
	}
	if len(set.IPs) != 2 {
		t.Fatalf("adresses : %v", set.IPs)
	}
	for _, n := range set.DNSNames {
		if n == "localhost" {
			t.Fatal("localhost ajouté")
		}
	}
}
