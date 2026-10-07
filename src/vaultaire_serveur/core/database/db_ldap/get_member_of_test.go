package dbldap

import (
	"reflect"
	"testing"
)

// TO-DO 155 : `memberOf` se lit en lot, pour les deux chemins de recherche. Ce
// qui se joue sans base est le REGROUPEMENT par compte.

func app(compte, groupe, domaine string) ligneDAppartenance {
	return ligneDAppartenance{compte: compte, groupe: groupe, domaine: domaine}
}

func TestLesAppartenancesSontRangeesParCompte(t *testing.T) {
	a := assemblerAppartenances([]ligneDAppartenance{
		app("alice", "Dev", "dev.acme.lan"),
		app("alice", "Equipe", "acme.lan"),
		app("alice", "Secrets", "dev.acme.lan"),
		app("bob", "Dev", "dev.acme.lan"),
	})

	voulu := []GroupDomain{
		{GroupName: "Dev", DomainName: "dev.acme.lan"},
		{GroupName: "Equipe", DomainName: "acme.lan"},
		{GroupName: "Secrets", DomainName: "dev.acme.lan"},
	}
	if !reflect.DeepEqual(a.De("alice"), voulu) {
		t.Errorf("groupes d'alice = %v, attendu %v", a.De("alice"), voulu)
	}
	if got := a.De("bob"); len(got) != 1 || got[0].GroupName != "Dev" {
		t.Errorf("groupes de bob = %v, attendu [Dev]", got)
	}
}

// Le groupe du domaine PARENT est là : c'est lui qui manquait à une recherche
// faite sous le sous-domaine.
func TestUnGroupeHorsDuSousDomaineNEstPasPerdu(t *testing.T) {
	a := assemblerAppartenances([]ligneDAppartenance{
		app("alice", "Equipe", "acme.lan"),
		app("alice", "Dev", "dev.acme.lan"),
		app("alice", "Compta", "paris.fr"),
	})
	domaines := map[string]bool{}
	for _, g := range a.De("alice") {
		domaines[g.DomainName] = true
	}
	for _, d := range []string{"acme.lan", "dev.acme.lan", "paris.fr"} {
		if !domaines[d] {
			t.Errorf("le groupe de %s manque : %v", d, a.De("alice"))
		}
	}
}

// La base compare les noms sans la casse ; une table Go, non. Un compte rendu
// sous une autre casse que celle demandée ne doit pas perdre ses groupes.
func TestLaCasseDuCompteNeComptePas(t *testing.T) {
	a := assemblerAppartenances([]ligneDAppartenance{app("Alice.Martin", "Equipe", "acme.lan")})
	for _, demande := range []string{"alice.martin", "ALICE.MARTIN", " Alice.Martin "} {
		if len(a.De(demande)) != 1 {
			t.Errorf("De(%q) ne rend rien : %v", demande, a)
		}
	}
}

// Un compte sans groupe, ou inconnu, n'a aucun groupe — sans erreur ni panique.
func TestUnCompteAbsentNARien(t *testing.T) {
	a := assemblerAppartenances(nil)
	if got := a.De("personne"); got != nil {
		t.Errorf("De(personne) = %v, attendu rien", got)
	}
	var vide Appartenances
	if got := vide.De("personne"); got != nil {
		t.Errorf("table nulle : De rend %v", got)
	}
}

// Deux lots ne se recouvrent pas, mais rien ne doit en dépendre : une ligne
// rendue deux fois ne compte qu'une fois.
func TestUneLigneEnDoubleNeCompteQuUneFois(t *testing.T) {
	a := assemblerAppartenances([]ligneDAppartenance{
		app("alice", "Equipe", "acme.lan"),
		app("ALICE", "Equipe", "acme.lan"),
		app("alice", "", "acme.lan"),
		app("", "Equipe", "acme.lan"),
	})
	if got := a.De("alice"); len(got) != 1 {
		t.Errorf("groupes d'alice = %v, attendu un seul", got)
	}
	if len(a) != 1 {
		t.Errorf("%d comptes rendus, attendu 1 : %v", len(a), a)
	}
}

// Sans nom, aucune requête : la fonction ne touche pas à la base.
func TestSansNomAucuneLecture(t *testing.T) {
	a, err := GetMemberOfByUsernames(nil, []string{"", "  "})
	if err != nil || len(a) != 0 {
		t.Errorf("GetMemberOfByUsernames(vide) = %v, %v", a, err)
	}
}

// Un nom qui n'est pas un identifiant est refusé avant toute requête.
func TestUnNomInvalideEstRefuse(t *testing.T) {
	if _, err := GetMemberOfByUsernames(nil, []string{"alice", "x' OR '1'='1"}); err == nil {
		t.Error("un nom portant une apostrophe a été accepté")
	}
}
