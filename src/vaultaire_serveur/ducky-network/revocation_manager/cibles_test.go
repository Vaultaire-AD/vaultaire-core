package revocationmanager

import (
	"os"
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

// Une levée vise aussi les machines que le verrouillage avait visées (TO-DO 49).
func TestLaLeveeAjouteLesMachinesSousVerrou(t *testing.T) {
	cibles, ajoutees := ajouterLesCibles([]string{"pc-01", "pc-03"}, []string{"PC-01", "pc-02", "", "pc-02"})
	if ajoutees != 1 || len(cibles) != 3 || cibles[0] != "pc-01" || cibles[1] != "pc-02" || cibles[2] != "pc-03" {
		t.Fatalf("cibles = %v (%d ajoutée(s)) — attendu pc-01, pc-02, pc-03 et une seule ajoutée : "+
			"pc-01 y était déjà, à la casse près, et pc-02 ne compte qu'une fois", cibles, ajoutees)
	}
	if cibles, ajoutees := ajouterLesCibles(nil, nil); len(cibles) != 0 || ajoutees != 0 {
		t.Fatalf("liste vide : %v, %d", cibles, ajoutees)
	}
}

// Le repère « sous verrou » se lit AVANT la levée, qui l'efface. Par le texte :
// Trigger lit la base et pousse sur le réseau, le jouer demanderait les deux.
func TestLesMachinesSousVerrouSontLuesAvantLaLevee(t *testing.T) {
	brut, err := os.ReadFile("dispatch.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(brut)
	lecture := strings.Index(source, "dbrevocation.MachinesSousVerrou(")
	levee := strings.Index(source, "dbrevocation.LiftSoftRevocations(")
	ecriture := strings.Index(source, "dbrevocation.CreateOrder(")
	if lecture < 0 || levee < 0 || ecriture < 0 {
		t.Fatalf("repères introuvables dans dispatch.go (%d, %d, %d)", lecture, levee, ecriture)
	}
	if !(lecture < levee && levee < ecriture) {
		t.Fatal("ordre attendu : machines sous verrou, levée, écriture de l'ordre. Lues après la levée, " +
			"elles sont toujours vides — et une machine qui avait verrouillé ne reçoit jamais la levée")
	}
}
