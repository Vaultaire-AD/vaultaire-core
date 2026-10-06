package revocationmanager

import (
	"strings"
	"testing"
)

// TO-DO 133 — qui reçoit l'ordre.
//
// Les cibles venaient des seuls GROUPES. Une machine où le compte tenait une
// session, mais dont il avait été retiré depuis, n'était jamais visée — et la
// commande affichait un succès.

func TestUneSessionOuverteSuffitAViserLaMachine(t *testing.T) {
	cibles, avecSession, horsGroupes := reunirLesCibles(
		[]string{"pc-b", "pc-a"},
		[]string{"pc-c", "pc-a"},
	)

	if got := strings.Join(cibles, ","); got != "pc-a,pc-b,pc-c" {
		t.Fatalf("cibles = %s, attendu pc-a,pc-b,pc-c — pc-c n'est dans aucun groupe du compte, "+
			"mais il y travaille en ce moment", got)
	}
	if avecSession != 2 {
		t.Errorf("machines avec session = %d, attendu 2", avecSession)
	}
	if horsGroupes != 1 {
		t.Errorf("machines visees pour leur seule session = %d, attendu 1", horsGroupes)
	}
}

// Une machine ne reçoit l'ordre qu'UNE fois, qu'elle vienne des deux listes ou
// que la base la rende deux fois.
func TestAucuneCibleEnDouble(t *testing.T) {
	cibles, avecSession, _ := reunirLesCibles(
		[]string{"pc-a", "pc-a", "pc-b"},
		[]string{"pc-a", "pc-a", ""},
	)
	if len(cibles) != 2 {
		t.Errorf("cibles = %v, attendu deux machines distinctes", cibles)
	}
	if avecSession != 1 {
		t.Errorf("machines avec session = %d, attendu 1 — deux lignes d'une meme machine font une machine", avecSession)
	}
}

// Sans session lisible, l'ordre part quand même vers les machines des groupes :
// une lecture en échec ne doit pas désarmer le kill switch.
func TestSansSessionLesGroupesSuffisent(t *testing.T) {
	cibles, avecSession, horsGroupes := reunirLesCibles([]string{"pc-b", "pc-a"}, nil)
	if strings.Join(cibles, ",") != "pc-a,pc-b" || avecSession != 0 || horsGroupes != 0 {
		t.Errorf("cibles = %v, %d, %d", cibles, avecSession, horsGroupes)
	}
}

// Un compte sans groupe mais en session : la seule machine à joindre est celle
// où il se trouve.
func TestUnCompteSansGroupeEnSessionEstVise(t *testing.T) {
	cibles, _, horsGroupes := reunirLesCibles(nil, []string{"pc-z"})
	if len(cibles) != 1 || cibles[0] != "pc-z" || horsGroupes != 1 {
		t.Errorf("cibles = %v (hors groupes %d), attendu la machine de la session", cibles, horsGroupes)
	}
}
