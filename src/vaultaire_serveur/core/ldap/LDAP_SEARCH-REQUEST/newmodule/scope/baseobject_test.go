package scope

import "testing"

func TestEntryInVaultaireSubtree_DomainSearch(t *testing.T) {
	base := "dc=bastion,dc=admin,dc=enov,dc=local"
	entries := []string{
		"uid=adm-lviguie,ou=users,dc=enov,dc=local",
		"cn=bastion,ou=groups,dc=enov,dc=local",
		"ou=users,dc=enov,dc=local",
	}
	for _, dn := range entries {
		if !entryMatchesBaseObject(dn, base, 2) {
			t.Fatalf("expected %q to match base %q in subtree scope", dn, base)
		}
	}
}

func TestEntryInVaultaireSubtree_RejectsUnrelatedDomain(t *testing.T) {
	base := "dc=bastion,dc=admin,dc=enov,dc=local"
	dn := "uid=other,ou=users,dc=other,dc=local"
	if entryMatchesBaseObject(dn, base, 2) {
		t.Fatalf("expected %q not to match base %q", dn, base)
	}
}
