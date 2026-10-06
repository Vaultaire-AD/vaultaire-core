package permission

import (
	"fmt"
	"strings"
	"testing"
)

// Le refus explicite (TO-DO 104).
//
// # Ce que ces tests gardent
//
//   - « nil » sur un groupe ne retire RIEN : un autre groupe accorde, c'est
//     accordé. C'est la valeur de toute action jamais réglée ; la rendre
//     prioritaire retirerait presque tous les droits du parc ;
//   - « deny » sur un groupe l'emporte sur TOUT, « all » compris, quel que soit
//     l'ordre des groupes, sur chaque chemin d'évaluation ;
//   - le groupe protégé n'est jamais soumis à un refus.

const cle = "write:update:user"

// droits installe les valeurs par groupe, et l'appartenance au groupe protégé.
func droits(t *testing.T, valeurs map[int]string, protege bool) {
	t.Helper()
	ancienLire, ancienExempte := lireContenuPermission, estExempteDesRefus
	lireContenuPermission = func(groupID int, action string) (string, error) {
		if action != cle {
			return "nil", nil
		}
		v, ok := valeurs[groupID]
		if !ok {
			return "", fmt.Errorf("groupe %d illisible", groupID)
		}
		return v, nil
	}
	estExempteDesRefus = func([]int) bool { return protege }
	t.Cleanup(func() { lireContenuPermission, estExempteDesRefus = ancienLire, ancienExempte })
}

func TestNilNeRetireRien(t *testing.T) {
	droits(t, map[int]string{1: "nil", 2: "(1:acme.lan)"}, false)
	if ok, motif := CheckPermissionsMultipleDomains([]int{1, 2}, cle, []string{"rh.acme.lan"}); !ok {
		t.Errorf("« nil » sur le groupe 1 a retiré ce que le groupe 2 accorde : %s", motif)
	}
	if ok, motif := CheckPermissionsAllDomains([]int{1, 2}, cle, nil); ok {
		t.Errorf("sans domaine, seul « all » passe ; accordé : %s", motif)
	}
	if !HasActionAnywhere([]int{1, 2}, cle) {
		t.Error("HasActionAnywhere : « nil » a fermé la porte d'entrée")
	}
	if p := DomainsWhereAllowed([]int{1, 2}, cle); !p.Allows("rh.acme.lan") {
		t.Error("DomainsWhereAllowed : « nil » a vidé le périmètre")
	}
}

func TestDenyLEmporteSurTout(t *testing.T) {
	for _, ordre := range [][]int{{1, 2}, {2, 1}} {
		droits(t, map[int]string{1: "deny", 2: "all"}, false)

		if ok, _ := CheckPermissionsMultipleDomains(ordre, cle, []string{"acme.lan"}); ok {
			t.Errorf("groupes %v : « all » d'un groupe l'emporte sur le « deny » de l'autre", ordre)
		}
		if ok, _ := CheckPermissionsMultipleDomains(ordre, cle, nil); ok {
			t.Errorf("groupes %v, sans domaine : le refus ne tient pas", ordre)
		}
		if ok, _ := CheckPermissionsAllDomains(ordre, cle, nil); ok {
			t.Errorf("groupes %v, contrôle strict : le refus ne tient pas", ordre)
		}
		// Avec domaines, le refus doit tomber AVANT le contrôle du domaine
		// protégé, qui lirait la base : s'il ne tombait pas, ce test paniquerait.
		if ok, _ := CheckPermissionsAllDomains(ordre, cle, []string{"acme.lan"}); ok {
			t.Errorf("groupes %v, contrôle strict sur un domaine : le refus ne tient pas", ordre)
		}
		if HasActionAnywhere(ordre, cle) {
			t.Errorf("groupes %v : la porte d'entrée reste ouverte malgré le refus", ordre)
		}
		if p := DomainsWhereAllowed(ordre, cle); !p.IsEmpty() {
			t.Errorf("groupes %v : périmètre %+v malgré le refus", ordre, p)
		}
	}
}

func TestDenyNeVautQuePourSonAction(t *testing.T) {
	droits(t, map[int]string{1: "deny", 2: "all"}, false)
	ancien := lireContenuPermission
	lireContenuPermission = func(groupID int, action string) (string, error) {
		if action == "read:get:user" {
			return "all", nil
		}
		return ancien(groupID, action)
	}
	if ok, motif := CheckPermissionsMultipleDomains([]int{1, 2}, "read:get:user", []string{"acme.lan"}); !ok {
		t.Errorf("un refus sur %s a retiré read:get:user : %s", cle, motif)
	}
}

func TestLeGroupeProtegeEchappeAuRefus(t *testing.T) {
	droits(t, map[int]string{1: "deny", 2: "all"}, true)
	if ok, motif := CheckPermissionsMultipleDomains([]int{1, 2}, cle, []string{"acme.lan"}); !ok {
		t.Errorf("membre du groupe protégé refusé : %s — un « deny » mal posé ne pourrait plus être levé", motif)
	}
	if !HasActionAnywhere([]int{1, 2}, cle) {
		t.Error("membre du groupe protégé : porte d'entrée fermée par un refus")
	}
	// Exempté du refus ne veut pas dire accordé : le groupe qui refuse
	// n'accorde rien pour autant.
	droits(t, map[int]string{1: "deny"}, true)
	if ok, _ := CheckPermissionsMultipleDomains([]int{1}, cle, []string{"acme.lan"}); ok {
		t.Error("l'exemption a transformé un refus en accord")
	}
}

func TestUnGroupeIllisibleNEstPasUnRefus(t *testing.T) {
	// Groupe 9 absent : sa lecture échoue. Ce n'est ni un accord, ni un refus.
	droits(t, map[int]string{2: "(0:acme.lan)"}, false)
	if ok, motif := CheckPermissionsMultipleDomains([]int{9, 2}, cle, []string{"acme.lan"}); !ok {
		t.Errorf("une lecture en échec a refusé ce qu'un autre groupe accorde : %s", motif)
	}
}

func TestLaGrammaireDistingueNilEtDeny(t *testing.T) {
	if p := ParsePermissionContent("nil"); !p.Aucun || p.Refus {
		t.Errorf("nil lu %+v", p)
	}
	if p := ParsePermissionContent("deny"); !p.Refus || p.Aucun {
		t.Errorf("deny lu %+v", p)
	}
	if pa := ParsePermissionAction("deny"); pa.Type != ValeurRefus {
		t.Errorf("ParsePermissionAction(deny).Type = %q : lu comme une liste de domaines vide", pa.Type)
	}
	if s := ConvertPermissionActionToString(ParsePermissionAction("deny")); s != "deny" {
		t.Errorf("aller-retour de deny : %q", s)
	}
	// Une union ne dissout pas un refus ; nil reste neutre.
	cas := map[[2]string]string{
		{"deny", "all"}:          "deny",
		{"(1:acme.lan)", "deny"}: "deny",
		{"nil", "(1:acme.lan)"}:  "(1:acme.lan)",
		{"nil", "nil"}:           "nil",
	}
	for entree, attendu := range cas {
		if got := MergePermissionContent(entree[0], entree[1]); got != attendu {
			t.Errorf("MergePermissionContent(%q, %q) = %q, attendu %q", entree[0], entree[1], got, attendu)
		}
	}
	if !IsUserAuthorizedToSearch([]string{"(1:acme.lan)"}, "acme.lan") ||
		IsUserAuthorizedToSearch([]string{"(1:acme.lan)", "deny"}, "acme.lan") {
		t.Error("IsUserAuthorizedToSearch ne tient pas le refus")
	}
}

func TestLeMotifNommeLeRefus(t *testing.T) {
	droits(t, map[int]string{1: "all", 2: "deny"}, false)
	if m := MotifDeRefusExplicite([]int{1, 2}, cle); !strings.Contains(m, "groupe 2") {
		t.Errorf("motif %q : il doit nommer le groupe qui refuse", m)
	}
	droits(t, map[int]string{1: "nil"}, false)
	if m := MotifDeRefusExplicite([]int{1}, cle); m != "" {
		t.Errorf("motif %q pour un simple nil : ce n'est pas un refus", m)
	}
}
