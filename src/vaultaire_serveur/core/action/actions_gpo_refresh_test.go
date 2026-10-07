package action

import (
	"errors"
	"strings"
	"testing"

	"vaultaire/core/gpo"
)

// La demande de cycle à plusieurs machines — TO-DO 169. La boucle est partagée
// par la ligne de commande et le portail : c'est elle qu'on éprouve, sans core.

// rafraichissementDEssai remplace l'action par un parc fictif : chaque machine
// y est jointe, hors ligne, ou hors du périmètre de l'appelant.
func rafraichissementDEssai(t *testing.T, parc map[string]string) *[]Params {
	t.Helper()
	avant := executerLeRafraichissement
	var appels []Params
	executerLeRafraichissement = func(_ Appelant, p Params) (Resultat, error) {
		appels = append(appels, p)
		switch parc[p.Get("computeur_id")] {
		case "jointe":
			return Resultat{Donnees: true}, nil
		case "hors-ligne":
			return Resultat{Donnees: false}, nil
		default:
			return Resultat{}, errors.New("permission refusée")
		}
	}
	t.Cleanup(func() { executerLeRafraichissement = avant })
	return &appels
}

func TestLaDemandeDeCycleCompteCeQuElleAJoint(t *testing.T) {
	appels := rafraichissementDEssai(t, map[string]string{
		"PC-1": "jointe", "PC-2": "jointe", "PC-3": "hors-ligne", "PC-4": "refusee",
	})
	bilan := RafraichirMachines(Appelant{Username: "admin"}, []string{"PC-1", "PC-2", "PC-3", "PC-4"}, "essai")

	if bilan != (BilanRafraichissement{Visees: 4, Jointes: 2, NonJointes: 1, Refusees: 1}) {
		t.Fatalf("bilan %+v", bilan)
	}
	// Une demande par machine, ni plus ni moins : chacune est contrôlée pour
	// elle-même par l'action.
	if len(*appels) != 4 {
		t.Fatalf("%d appel(s) de l'action pour 4 machines", len(*appels))
	}
	for _, p := range *appels {
		if p.Get("motif") != "essai" {
			t.Errorf("le motif n'est pas transmis à %s : %q", p.Get("computeur_id"), p.Get("motif"))
		}
	}

	lisible := bilan.Lisible("liée(s) à la GPO base")
	for _, attendu := range []string{
		"Cycle demandé à 2 machine(s) sur 4 liée(s) à la GPO base.",
		"1 hors ligne ou non jointe(s)",
		"1 hors de votre périmètre n'ont pas été touchées",
	} {
		if !strings.Contains(lisible, attendu) {
			t.Errorf("le bilan ne dit pas %q : %s", attendu, lisible)
		}
	}
	// Les machines refusées sont comptées, jamais nommées.
	if strings.Contains(lisible, "PC-4") {
		t.Errorf("le bilan nomme une machine hors périmètre : %s", lisible)
	}
}

func TestUnBilanSansRienNeLInventePas(t *testing.T) {
	rafraichissementDEssai(t, nil)
	if got := RafraichirMachines(Appelant{}, nil, "").Lisible("liée(s) à la GPO vide"); !strings.Contains(got, "Aucune machine liée(s) à la GPO vide") {
		t.Errorf("aucune machine visée : %q", got)
	}
	tout := BilanRafraichissement{Visees: 3, Jointes: 3}.Lisible("connectée(s)")
	if tout != "Cycle demandé à 3 machine(s) sur 3 connectée(s)." {
		t.Errorf("tout le monde joint : %q — rien à ajouter", tout)
	}
}

// gpoDEssai remplace la lecture de la GPO et de ses machines.
func gpoDEssai(t *testing.T, policy *gpo.Policy, lectureRefusee error, machines []string) {
	t.Helper()
	avantLire, avantMachines := lireLaGPO, machinesDeLaGPO
	lireLaGPO = func(Appelant, string) (*gpo.Policy, error) { return policy, lectureRefusee }
	machinesDeLaGPO = func(id int) ([]string, error) {
		if policy == nil || id != policy.ID {
			t.Errorf("machines demandées pour la GPO %d", id)
		}
		return machines, nil
	}
	t.Cleanup(func() { lireLaGPO, machinesDeLaGPO = avantLire, avantMachines })
}

func TestLeCycleDUneGPOViseSesMachines(t *testing.T) {
	appels := rafraichissementDEssai(t, map[string]string{"PC-1": "jointe", "PC-2": "hors-ligne"})
	gpoDEssai(t, &gpo.Policy{ID: 7, Name: "base", Scope: gpo.ScopeMachine}, nil, []string{"PC-1", "PC-2"})

	bilan, err := RafraichirMachinesDeLaGPO(Appelant{Username: "admin"}, " base ")
	if err != nil {
		t.Fatal(err)
	}
	if bilan != (BilanRafraichissement{Visees: 2, Jointes: 1, NonJointes: 1}) {
		t.Fatalf("bilan %+v", bilan)
	}
	if len(*appels) != 2 || !strings.Contains((*appels)[0].Get("motif"), "GPO base") {
		t.Errorf("appels : %v — le motif doit nommer la GPO, il part dans le journal de l'agent", *appels)
	}
}

// Une GPO de COMPTE ne se rejoue pas par un cycle : on le dit, et aucune machine
// n'est sollicitée.
func TestLeCycleDUneGPODeCompteEstRefuseEtNeToucheRien(t *testing.T) {
	appels := rafraichissementDEssai(t, map[string]string{"PC-1": "jointe"})
	gpoDEssai(t, &gpo.Policy{ID: 8, Name: "env", Scope: gpo.ScopeUser}, nil, []string{"PC-1"})

	_, err := RafraichirMachinesDeLaGPO(Appelant{Username: "admin"}, "env")
	if !errors.Is(err, ErrGPODeCompte) {
		t.Fatalf("erreur %v, attendu ErrGPODeCompte", err)
	}
	if !strings.Contains(err.Error(), "ouverture de session") {
		t.Errorf("le refus ne dit pas QUAND une GPO de compte s'applique : %v", err)
	}
	if len(*appels) != 0 {
		t.Errorf("%d machine(s) sollicitée(s) pour une GPO de compte", len(*appels))
	}
}

// Qui n'a pas le droit de LIRE la GPO n'en énumère pas les machines.
func TestSansDroitDeLireLaGPOAucuneMachineNEstSollicitee(t *testing.T) {
	appels := rafraichissementDEssai(t, map[string]string{"PC-1": "jointe"})
	refus := errors.New("permission refusée : read:get:gpo")
	gpoDEssai(t, nil, refus, []string{"PC-1"})

	if _, err := RafraichirMachinesDeLaGPO(Appelant{Username: "x"}, "base"); !errors.Is(err, refus) {
		t.Fatalf("erreur %v, attendu le refus de lecture", err)
	}
	if len(*appels) != 0 {
		t.Errorf("%d machine(s) sollicitée(s) sans droit de lire la GPO", len(*appels))
	}
	if _, err := RafraichirMachinesDeLaGPO(Appelant{}, "  "); err == nil {
		t.Error("un nom de GPO vide est accepté")
	}
}
