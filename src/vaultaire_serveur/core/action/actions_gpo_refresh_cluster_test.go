package action

import (
	"strings"
	"testing"
	"time"

	dbgpo "vaultaire/core/database/db_gpo"
)

// TO-DO 172 : une machine connectée à un AUTRE core du cluster reçoit sa
// demande de cycle par la base, et le bilan le dit.

type clusterDEssai struct {
	ici      map[string]bool   // machines dont CE core tient le tunnel
	ailleurs map[string]string // machine -> core qui la tient
	cores    int               // autres cores en ligne
	ecrites  map[int64]string  // demande -> machine
	issues   map[int64]dbgpo.IssueDeDemande
}

func installerCluster(t *testing.T, c *clusterDEssai) {
	t.Helper()
	c.ecrites, c.issues = map[int64]string{}, map[int64]dbgpo.IssueDeDemande{}
	aP, aC, aE, aI, aD, aA := pousserIci, autresCores, ecrireDemande, issuesDes, dormir, AttenteDuRelais
	t.Cleanup(func() {
		pousserIci, autresCores, ecrireDemande, issuesDes, dormir, AttenteDuRelais = aP, aC, aE, aI, aD, aA
	})
	AttenteDuRelais = 300 * time.Millisecond
	dormir = func(time.Duration) { time.Sleep(10 * time.Millisecond) }
	pousserIci = func(id, motif string) (bool, error) { return c.ici[id], nil }
	autresCores = func() int { return c.cores }
	ecrireDemande = func(id, motif string) (int64, error) {
		n := int64(len(c.ecrites) + 1)
		c.ecrites[n] = id
		// Le core qui tient la machine la prend aussitôt, comme le ferait son
		// relais au tour suivant.
		if par, ok := c.ailleurs[id]; ok {
			c.issues[n] = dbgpo.IssueDeDemande{Prise: true, PrisePar: par, Remise: true}
		}
		return n, nil
	}
	issuesDes = func(ids []int64) (map[int64]dbgpo.IssueDeDemande, error) { return c.issues, nil }
}

func TestUneMachineDUnAutreCoreRecoitSaDemande(t *testing.T) {
	installerCluster(t, &clusterDEssai{ailleurs: map[string]string{"PC-B": "core2"}, cores: 1})
	res, err := rafraichirMachine(Appelant{Username: "admin"}, Params{"computeur_id": "PC-B"})
	if err != nil {
		t.Fatal(err)
	}
	issue := res.Donnees.(IssueCycle)
	if !issue.Remise || !issue.Relayee || issue.Par != "core2" {
		t.Errorf("issue %+v", issue)
	}
	if !strings.Contains(res.Message, "par le core core2") {
		t.Errorf("message : %s", res.Message)
	}
}

// Le constat du 172 : le bilan disait « hors ligne » d'une machine en ligne,
// ailleurs.
func TestHorsLigneVeutDireSurToutLeCluster(t *testing.T) {
	installerCluster(t, &clusterDEssai{cores: 1})
	res, _ := rafraichirMachine(Appelant{}, Params{"computeur_id": "PC-X"})
	if !strings.Contains(res.Message, "connectée à aucun core du cluster") {
		t.Errorf("message : %s", res.Message)
	}
}

// Sans autre core, rien n'est écrit en base : le comportement d'avant.
func TestSansClusterRienNEstRelaye(t *testing.T) {
	c := &clusterDEssai{cores: 0}
	installerCluster(t, c)
	res, _ := rafraichirMachine(Appelant{}, Params{"computeur_id": "PC-X"})
	if len(c.ecrites) != 0 {
		t.Errorf("%d demande(s) écrite(s) sans cluster", len(c.ecrites))
	}
	if !strings.Contains(res.Message, "hors ligne : elle rafraîchira") {
		t.Errorf("message : %s", res.Message)
	}
}

func TestLeBilanDuParcCompteLesMachinesDesAutresCores(t *testing.T) {
	installerCluster(t, &clusterDEssai{
		ici:      map[string]bool{"PC-A": true},
		ailleurs: map[string]string{"PC-B": "core2", "PC-C": "core3"},
		cores:    2,
	})
	// La boucle passe par l'action réelle, sans le contrôle de droits du
	// registre : c'est le décompte qu'on éprouve ici.
	avant := executerLeRafraichissement
	executerLeRafraichissement = func(a Appelant, p Params) (Resultat, error) { return rafraichirMachine(a, p) }
	t.Cleanup(func() { executerLeRafraichissement = avant })

	debut := time.Now()
	bilan := RafraichirMachines(Appelant{Username: "admin"}, []string{"PC-A", "PC-B", "PC-C", "PC-D"}, "essai")
	want := BilanRafraichissement{Visees: 4, Jointes: 3, JointesAilleurs: 2, NonJointes: 1, Relayees: 3}
	if bilan != want {
		t.Fatalf("bilan %+v, attendu %+v", bilan, want)
	}
	// Une seule attente pour tout le parc, pas une par machine.
	if d := time.Since(debut); d > 2*AttenteDuRelais {
		t.Errorf("le bilan a pris %s : l'attente est faite machine par machine ?", d)
	}
	lisible := bilan.Lisible("liée(s) à la GPO base")
	for _, attendu := range []string{
		"Cycle demandé à 3 machine(s) sur 4 liée(s) à la GPO base, dont 2 par un autre core du cluster.",
		"1 hors ligne (sur aucun core du cluster)",
	} {
		if !strings.Contains(lisible, attendu) {
			t.Errorf("le bilan ne dit pas %q : %s", attendu, lisible)
		}
	}
}
