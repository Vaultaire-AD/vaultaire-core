package candidate

import "testing"

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

	if len(dse.SupportedControl) != 0 {
		t.Errorf("SupportedControl = %v : aucun contrôle n'est traité, "+
			"les contrôles reçus sont refusés s'ils sont critiques", dse.SupportedControl)
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
