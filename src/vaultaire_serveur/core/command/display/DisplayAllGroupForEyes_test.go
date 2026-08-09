package display

import (
	"strings"
	"testing"

	"vaultaire/core/storage"
)

func arbre() *storage.DomainNode {
	fr := &storage.DomainNode{Name: "fr", Groups: []string{"zeta", "alpha"}}
	admin := &storage.DomainNode{Name: "admin", Groups: []string{"ops"}}
	fr.Children = map[string]*storage.DomainNode{"admin": admin}
	return &storage.DomainNode{
		Name:     "",
		Children: map[string]*storage.DomainNode{"fr": fr},
	}
}

// TestRacineNilNePaniquePas.
//
// L'ancienne version déréférençait root.Children sans garde. Un appelant qui
// n'a trouvé aucun domaine passe légitimement nil, et l'affichage est le
// dernier endroit où l'absence de données doit arrêter le programme.
func TestRacineNilNePaniquePas(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panique sur racine nil : %v", r)
		}
	}()
	if out := PrintDomainTreeRoot(nil); !strings.Contains(out, "Aucun domaine") {
		t.Errorf("racine nil rendue %q", out)
	}
}

// TestLAffichageNeModifiePasSonEntree est le test du défaut d'origine.
//
// `sort.Strings(node.Groups)` réordonne la tranche DE L'APPELANT : une
// fonction d'affichage modifiait la structure qu'on lui donnait à lire.
func TestLAffichageNeModifiePasSonEntree(t *testing.T) {
	racine := arbre()
	avant := append([]string(nil), racine.Children["fr"].Groups...)

	PrintDomainTreeRoot(racine)

	apres := racine.Children["fr"].Groups
	for i := range avant {
		if avant[i] != apres[i] {
			t.Fatalf("l'affichage a réordonné les groupes de l'appelant : %v → %v",
				avant, apres)
		}
	}
}

// TestOrdreStable : le parcours d'une map Go est volontairement aléatoire.
// Sans tri, deux affichages de la même arborescence sortent différemment, ce
// qui se lit comme un changement de la structure.
func TestOrdreStable(t *testing.T) {
	premier := PrintDomainTreeRoot(arbre())
	for i := 0; i < 20; i++ {
		if out := PrintDomainTreeRoot(arbre()); out != premier {
			t.Fatalf("sortie instable à l'itération %d :\n%s\n---\n%s", i, premier, out)
		}
	}
	if strings.Index(premier, "alpha") > strings.Index(premier, "zeta") {
		t.Errorf("groupes non triés :\n%s", premier)
	}
}

// TestDernierTraitDuNiveau : le glyphe └── ne doit apparaître qu'en fin de
// fratrie. Un groupe suivi d'un sous-domaine n'est pas le dernier trait.
func TestDernierTraitDuNiveau(t *testing.T) {
	out := PrintDomainTreeRoot(arbre())

	var ligneGroupe string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "zeta") {
			ligneGroupe = l
		}
	}
	if ligneGroupe == "" {
		t.Fatalf("groupe absent :\n%s", out)
	}
	// « zeta » est le dernier groupe de fr, mais fr a un sous-domaine après :
	// le trait doit rester ├──.
	if strings.Contains(ligneGroupe, "└──") {
		t.Errorf("dernier trait posé alors qu'un sous-domaine suit :\n%s", out)
	}
	// Le domaine complet doit figurer sur la ligne : il faut le saisir tel
	// quel dans les commandes.
	if !strings.Contains(ligneGroupe, "(fr)") {
		t.Errorf("domaine complet absent de la ligne de groupe : %q", ligneGroupe)
	}
}
