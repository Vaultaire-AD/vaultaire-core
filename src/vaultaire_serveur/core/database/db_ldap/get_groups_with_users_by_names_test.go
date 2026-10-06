package dbldap

import (
	"reflect"
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// TO-DO 131 : la lecture des groupes se fait en lot. Ce qui se joue sans base,
// c'est le REGROUPEMENT — ce que l'ancienne boucle, une requête par groupe,
// garantissait sans y penser.

func ligne(groupe, domaine, membre string) ligneDeGroupe {
	return ligneDeGroupe{groupe: groupe, domaine: domaine, membre: membre,
		creeLe: "2026-01-01 00:00:00", modifieLe: "2026-02-02 00:00:00", entryUUID: "uuid-" + groupe}
}

func TestLesGroupesSortentDansLOrdreDemande(t *testing.T) {
	// La base trie par nom ; l'appelant, lui, a demandé « ventes » d'abord.
	lignes := []ligneDeGroupe{
		ligne("admins", "enov.local", "alice"),
		ligne("admins", "enov.local", "bob"),
		ligne("ventes", "paris.enov.local", "chloe"),
	}

	groupes := assemblerGroupes(lignes, []string{"ventes", "admins"})

	if len(groupes) != 2 || groupes[0].GroupName != "ventes" || groupes[1].GroupName != "admins" {
		t.Fatalf("ordre rendu = %v : le résolveur construit ses entrées dans l'ordre reçu, "+
			"et une recherche rejouée doit rendre la même chose", noms(groupes))
	}
	if !reflect.DeepEqual(groupes[1].Users, []string{"alice", "bob"}) {
		t.Errorf("membres de admins = %v, attendu [alice bob]", groupes[1].Users)
	}
	if groupes[0].DomainName != "paris.enov.local" || groupes[0].EntryUUID != "uuid-ventes" {
		t.Errorf("groupe ventes mal assemblé : %+v", groupes[0])
	}
}

// Un nom demandé que la base ne rend pas — groupe inconnu, ou groupe sans
// membre, que la jointure interne écarte — manque au résultat sans rien casser.
func TestUnGroupeAbsentManqueSansErreur(t *testing.T) {
	groupes := assemblerGroupes(
		[]ligneDeGroupe{ligne("admins", "enov.local", "alice")},
		[]string{"fantome", "admins", "vide"})

	if len(groupes) != 1 || groupes[0].GroupName != "admins" {
		t.Fatalf("résultat = %v, attendu [admins]", noms(groupes))
	}
}

// La comparaison SQL ignore la casse, pas celle d'une table Go : un groupe rendu
// sous un nom qui ne figure pas tel quel dans la liste ne doit pas disparaître.
func TestUnGroupeRenduSousUneAutreCasseNEstPasPerdu(t *testing.T) {
	groupes := assemblerGroupes(
		[]ligneDeGroupe{ligne("Admins", "enov.local", "alice")},
		[]string{"admins"})

	if len(groupes) != 1 || groupes[0].GroupName != "Admins" {
		t.Fatalf("résultat = %v : le groupe lu en base a été écarté parce que son nom "+
			"diffère par la casse de celui demandé", noms(groupes))
	}
}

func TestLesDoublonsEtLesVidesSontRetiresAvantLaRequete(t *testing.T) {
	got := sansDoublons([]string{"admins", "", "ventes", "admins", "  "})
	if !reflect.DeepEqual(got, []string{"admins", "ventes"}) {
		t.Fatalf("sansDoublons = %v : un nom répété produirait deux fois le même groupe, "+
			"un nom vide une requête qui ne peut rien rendre", got)
	}
}

func TestAucunNomNeDeclencheAucuneRequete(t *testing.T) {
	// db nil : la fonction paniquerait si elle interrogeait la base.
	groupes, err := GetGroupsWithUsersByNames(nil, []string{"", " "})
	if err != nil || len(groupes) != 0 {
		t.Fatalf("groupes=%v err=%v, attendu une liste vide sans erreur", groupes, err)
	}
}

func noms(groupes []ldapstorage.Group) []string {
	out := make([]string, len(groupes))
	for i, g := range groupes {
		out[i] = g.GroupName
	}
	return out
}
