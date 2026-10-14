package pamcommunication

import (
	"testing"
	"time"

	"vaultaire_client/gpo"
)

// TO-DO 198 : la phase GPO de compte ne retient pas l'ouverture de session
// au-delà de son plafond, et le cycle n'est pas abandonné pour autant.

func plafondCourt(t *testing.T, cycle func(string, string) gpo.Report) {
	t.Helper()
	ancienP, ancienC := PlafondGPOConnexion, lancerCycleUtilisateur
	PlafondGPOConnexion, lancerCycleUtilisateur = 150*time.Millisecond, cycle
	t.Cleanup(func() { PlafondGPOConnexion, lancerCycleUtilisateur = ancienP, ancienC })
}

func TestUnCycleLentRendLaMainAuPlafond(t *testing.T) {
	termine := make(chan struct{})
	plafondCourt(t, func(cle, compte string) gpo.Report {
		time.Sleep(600 * time.Millisecond)
		close(termine)
		return gpo.Report{Status: gpo.StatusApplied}
	})

	debut := time.Now()
	aTemps := applyUserGPO("alice@dom", "cle")
	duree := time.Since(debut)

	if aTemps {
		t.Error("un cycle de 600 ms est annoncé fini dans un plafond de 150 ms")
	}
	if duree < 140*time.Millisecond || duree > 450*time.Millisecond {
		t.Errorf("la main est rendue après %s, attendu ≈ 150 ms", duree)
	}
	// Le cycle continue : il n'est ni tué ni oublié.
	select {
	case <-termine:
	case <-time.After(2 * time.Second):
		t.Error("le cycle poursuivi en arrière-plan ne s'est jamais terminé")
	}
}

func TestUnCycleRapideEstAttendu(t *testing.T) {
	appele := false
	plafondCourt(t, func(cle, compte string) gpo.Report {
		appele = cle == "cle" && compte == "alice@dom"
		return gpo.Report{Status: gpo.StatusApplied}
	})
	if !applyUserGPO("alice@dom", "cle") {
		t.Error("un cycle immédiat est annoncé hors plafond")
	}
	if !appele {
		t.Error("le cycle n'a pas reçu la clé et le compte")
	}
}

func TestSansCleDeSessionAucunCycle(t *testing.T) {
	plafondCourt(t, func(string, string) gpo.Report {
		t.Error("cycle lancé sans clé de session")
		return gpo.Report{}
	})
	if !applyUserGPO("alice@dom", "") {
		t.Error("sans clé, rien n'attend : la fonction doit rendre vrai")
	}
}
