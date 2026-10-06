package candidate

import (
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// TestRootDSENAnnonceQueCeQuiExiste.
//
// Le RootDSE est un contrat : un client le lit pour savoir quoi tenter. Annoncer
// une capacité absente ne dégrade pas le service, elle le casse chez le client —
// et pour StartTLS, elle peut le faire poursuivre en clair avec les identifiants.
//
// Ce test échouera le jour où quelqu'un ajoutera une annonce. C'est voulu :
// l'ajout doit venir AVEC l'implémentation, dans le même commit.
func TestRootDSENAnnonceQueCeQuiExiste(t *testing.T) {
	dse := NewRootDSE()

	// Les contrôles annoncés sont EXACTEMENT ceux que le dispatcheur traite : la
	// liste est la même variable (point 130). La pagination a été annoncée sans
	// être traitée, et un client qui pagine bouclait alors sur la même page.
	if len(dse.SupportedControl) != len(ldapstorage.ControlesGeres) {
		t.Fatalf("SupportedControl = %v, ControlesGeres = %v : annonce et traitement divergent",
			dse.SupportedControl, ldapstorage.ControlesGeres)
	}
	for i, oid := range ldapstorage.ControlesGeres {
		if dse.SupportedControl[i] != oid {
			t.Errorf("SupportedControl[%d] = %q, ControlesGeres[%d] = %q", i, dse.SupportedControl[i], i, oid)
		}
	}
	if len(dse.SupportedControl) != 1 || dse.SupportedControl[0] != "1.2.840.113556.1.4.319" {
		t.Errorf("SupportedControl = %v : seule la pagination est implémentée. Un contrôle de plus "+
			"s'ajoute ici AVEC son traitement, dans le même commit", dse.SupportedControl)
	}
	// Modifier ce que rend NewRootDSE ne doit pas abîmer la liste du dispatcheur.
	dse.SupportedControl[0] = "altéré"
	if ldapstorage.ControlesGeres[0] != ldapstorage.OIDPagedResults {
		t.Error("le RootDSE partage son tableau avec ControlesGeres : le modifier change ce que le serveur accepte")
	}
	if len(dse.SupportedExtension) != 0 {
		t.Errorf("SupportedExtension = %v : StartTLS n'est pas implémenté, "+
			"l'annoncer peut faire poursuivre un client en clair", dse.SupportedExtension)
	}
	if len(dse.SupportedSASLMechanisms) != 0 {
		t.Errorf("SupportedSASLMechanisms = %v : seul le bind SIMPLE est géré",
			dse.SupportedSASLMechanisms)
	}

	// Ce qui reste doit être vrai, et le rester.
	if len(dse.SupportedLDAPVersion) != 1 || dse.SupportedLDAPVersion[0] != "3" {
		t.Errorf("SupportedLDAPVersion = %v, attendu [3]", dse.SupportedLDAPVersion)
	}
	if dse.SubschemaSubentry != "cn=schema" {
		t.Errorf("SubschemaSubentry = %q, attendu cn=schema", dse.SubschemaSubentry)
	}
	if dse.DN() != "" {
		t.Errorf("DN() = %q, le RootDSE a un DN vide (RFC 4512)", dse.DN())
	}
}
