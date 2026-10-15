package gpomanager

import (
	"errors"
	"testing"

	dbgpo "vaultaire/core/database/db_gpo"
)

// TO-DO 172 : un core ne remet que les demandes des machines qu'il tient, et
// une demande n'est remise qu'une fois.

type relaisDEssai struct {
	demandes []dbgpo.DemandeDeCycle
	tenues   map[string]bool
	prises   map[int64]string
	poussees []string
	notees   map[int64]bool
}

func (e *relaisDEssai) relais() relais {
	return relais{
		enAttente: func() ([]dbgpo.DemandeDeCycle, error) { return e.demandes, nil },
		tient:     func(id string) bool { return e.tenues[id] },
		prendre: func(id int64, par string) (bool, error) {
			if _, deja := e.prises[id]; deja {
				return false, nil
			}
			e.prises[id] = par
			return true, nil
		},
		pousser: func(id, motif string) (bool, error) {
			e.poussees = append(e.poussees, id+" | "+motif)
			return id != "PC-SANS-ENVOI", nil
		},
		noter: func(id int64, remise bool) error { e.notees[id] = remise; return nil },
	}
}

func nouveauRelais(tenues ...string) *relaisDEssai {
	e := &relaisDEssai{tenues: map[string]bool{}, prises: map[int64]string{}, notees: map[int64]bool{}}
	for _, t := range tenues {
		e.tenues[t] = true
	}
	return e
}

func TestUnCoreNeRemetQueSesMachines(t *testing.T) {
	e := nouveauRelais("PC-B")
	e.demandes = []dbgpo.DemandeDeCycle{
		{ID: 1, ComputeurID: "PC-A", Motif: "GPO base", DemandePar: "core1"},
		{ID: 2, ComputeurID: "PC-B", Motif: "GPO base", DemandePar: "core1"},
	}
	if n := RemettreLesDemandes(e.relais(), "core2"); n != 1 {
		t.Fatalf("%d remise(s), attendu 1", n)
	}
	if _, pris := e.prises[1]; pris {
		t.Error("la demande de PC-A, que ce core ne tient pas, a été prise : le core qui la tient ne la verrait plus")
	}
	if e.prises[2] != "core2" || !e.notees[2] {
		t.Errorf("PC-B : prise %q, remise %v", e.prises[2], e.notees[2])
	}
	if len(e.poussees) != 1 || e.poussees[0] != "PC-B | GPO base (relayée par core1)" {
		t.Errorf("poussées : %v", e.poussees)
	}
}

// Deux cores qui tiennent tous deux la machine (reconnexion en cours) : un seul
// la remet.
func TestUneDemandeNEstRemiseQuUneFois(t *testing.T) {
	e := nouveauRelais("PC-B")
	e.demandes = []dbgpo.DemandeDeCycle{{ID: 7, ComputeurID: "PC-B", DemandePar: "core1"}}
	r := e.relais()
	premier := RemettreLesDemandes(r, "core2")
	second := RemettreLesDemandes(r, "core3")
	if premier+second != 1 || len(e.poussees) != 1 {
		t.Errorf("remises %d + %d, %d poussée(s) : attendu une seule", premier, second, len(e.poussees))
	}
}

func TestUnEnvoiQuiEchoueEstNote(t *testing.T) {
	e := nouveauRelais("PC-SANS-ENVOI")
	e.demandes = []dbgpo.DemandeDeCycle{{ID: 3, ComputeurID: "PC-SANS-ENVOI"}}
	if n := RemettreLesDemandes(e.relais(), "core2"); n != 0 {
		t.Errorf("%d remise(s), attendu 0", n)
	}
	if remise, vu := e.notees[3]; !vu || remise {
		t.Errorf("l'échec n'est pas noté (vu %v, remise %v)", vu, remise)
	}
}

func TestUneBaseIllisibleNeRemetRien(t *testing.T) {
	r := nouveauRelais("PC-B").relais()
	r.enAttente = func() ([]dbgpo.DemandeDeCycle, error) { return nil, errors.New("base") }
	if n := RemettreLesDemandes(r, "core2"); n != 0 {
		t.Errorf("%d remise(s)", n)
	}
}

// `--all` vise tout le cluster : les machines de la base s'ajoutent à celles de
// ce core, sans doublon.
func TestMachinesDuClusterAjouteLaBase(t *testing.T) {
	ids := MachinesDuCluster(func() ([]string, error) { return []string{"PC-B", " PC-B ", "", "PC-C"}, nil })
	vus := map[string]int{}
	for _, id := range ids {
		vus[id]++
	}
	if vus["PC-B"] != 1 || vus["PC-C"] != 1 || vus[""] != 0 {
		t.Errorf("machines : %v", ids)
	}
	if got := MachinesDuCluster(func() ([]string, error) { return nil, errors.New("base") }); len(got) != 0 {
		t.Errorf("base illisible : %v (attendu les seules machines de ce core, aucune ici)", got)
	}
}
