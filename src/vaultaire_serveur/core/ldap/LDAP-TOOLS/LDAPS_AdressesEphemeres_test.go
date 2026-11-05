package ldaptools

import (
	"net"
	"testing"
)

func TestEnKubernetesLAdresseDuPodNEstPasReclamee(t *testing.T) {
	set := SANSet{
		DNSNames: []string{"vaultaire-0", "ldap.acme.lan"},
		IPs:      []net.IP{net.ParseIP("10.42.0.11"), net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.10")},
	}
	got := sansAdressesDetectees(set, []string{"10.0.0.10"})
	if len(got.DNSNames) != 2 {
		t.Fatalf("les noms doivent rester réclamés : %v", got.DNSNames)
	}
	if len(got.IPs) != 2 {
		t.Fatalf("adresses gardées %v : attendu 127.0.0.1 et l'adresse déclarée", got.IPs)
	}
	for _, ip := range got.IPs {
		if ip.String() == "10.42.0.11" {
			t.Fatal("l'adresse du pod est encore réclamée")
		}
	}
}

func TestHorsKubernetesRienNeChange(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	set := SANSet{IPs: []net.IP{net.ParseIP("192.168.1.5")}}
	if got := AttendusPourAudit(set, nil); len(got.IPs) != 1 {
		t.Fatalf("%v", got.IPs)
	}
}
