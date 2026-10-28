package miseajour

import (
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// Les résultats : les mêmes chaînes que le core (core/miseajour), qui les
// range en base et décide d'après elles.
func TestLesResultatsSontCeuxDuCore(t *testing.T) {
	for got, attendu := range map[string]string{
		ResultatInstalle: "installe", ResultatEchec: "echec",
		ResultatRefuse: "refuse", ResultatNonPrisEnCharge: "non_pris_en_charge",
	} {
		if got != attendu {
			t.Errorf("%q, le core écrit %q", got, attendu)
		}
	}
}

func TestLireOrdre(t *testing.T) {
	o, err := LireOrdre("2.4.0\nreleases\nnon")
	if err != nil || o.Version != "2.4.0" || o.Depot != "releases" || o.Retrograder {
		t.Fatalf("%+v %v", o, err)
	}
	if o, _ := LireOrdre("2.2.0\nsite\noui\n"); !o.Retrograder {
		t.Error("rétrogradation non lue")
	}
	for _, m := range []string{"", "2.4.0\nreleases", "2.4\nreleases\nnon", "2.4.0-rc1\nreleases\nnon",
		"2.4.0\n../x\nnon", "2.4.0\nreleases\npeut-être", "2.4.0\nreleases\nnon\nde trop"} {
		if _, err := LireOrdre(m); err == nil {
			t.Errorf("%q accepté", m)
		}
	}
}

func avecVersion(t *testing.T, v string) {
	t.Helper()
	avant := versionEnPlace
	t.Cleanup(func() { versionEnPlace = avant })
	versionEnPlace = func() string { return v }
}

func TestTraiter(t *testing.T) {
	appels := 0
	avant := Appliquer
	t.Cleanup(func() { Appliquer = avant })
	Appliquer = func(Ordre) (string, string) { appels++; return ResultatInstalle, "ok" }

	avecVersion(t, "2.3.0+gabc (2026-10-01)")
	if r, _ := Traiter(Ordre{Version: "2.3.0"}); r != ResultatInstalle || appels != 0 {
		t.Errorf("déjà en place : %s, %d appel(s)", r, appels)
	}
	if r, m := Traiter(Ordre{Version: "2.2.0"}); r != ResultatRefuse || !strings.Contains(m, "rétrogradation") || appels != 0 {
		t.Errorf("rétrogradation non demandée : %s %q", r, m)
	}
	if r, _ := Traiter(Ordre{Version: "2.2.0", Retrograder: true}); r != ResultatInstalle || appels != 1 {
		t.Errorf("rétrogradation demandée : %s, %d", r, appels)
	}
	if r, _ := Traiter(Ordre{Version: "2.4.0"}); r != ResultatInstalle || appels != 2 {
		t.Errorf("montée : %s, %d", r, appels)
	}
	avecVersion(t, "dev")
	if r, _ := Traiter(Ordre{Version: "2.4.0"}); r != ResultatRefuse || appels != 2 {
		t.Errorf("version en place illisible : %s", r)
	}
}

// Un agent qui ne peut pas se remplacer (pas root, pas sous systemd) répond
// tout de suite « non pris en charge » — le compte rendu part dans la réponse.
func TestUnOrdreNonPrisEnCharge(t *testing.T) {
	avant := systemdDirige
	t.Cleanup(func() { systemdDirige = avant })
	systemdDirige = func() bool { return false }
	avecVersion(t, "2.3.0")
	storage.Computeur_ID = "poste-1"
	rep := HandleTrame(storage.Trames_struct_client{Message_Order: []string{"09", "06"},
		SessionIntegritykey: "CLE", Content: "2.4.0\nreleases\nnon"}, nil)
	l := strings.Split(rep, "\n")
	if len(l) != 8 || l[0] != "09_04" || l[2] != "CLE" || l[4] != "poste-1" || l[5] != "2.4.0" ||
		l[6] != ResultatNonPrisEnCharge {
		t.Errorf("%q", rep)
	}
	if rep := HandleTrame(storage.Trames_struct_client{Message_Order: []string{"09", "02"},
		Content: "n'importe"}, nil); rep != "" {
		t.Errorf("ordre illisible : %q", rep)
	}
}

func TestLaDemande(t *testing.T) {
	var s suivi
	if s.doitDemander("CLE", false) {
		t.Error("demandé à un core sans la capacité")
	}
	if !s.doitDemander("CLE", true) {
		t.Error("pas demandé au démarrage")
	}
	s.derniereCle = "CLE"
	if s.doitDemander("CLE", true) {
		t.Error("redemandé sur la même session")
	}
	if !s.doitDemander("CLE2", true) || s.doitDemander("", true) {
		t.Error("tunnel rétabli / sans session")
	}
}

func TestLeCompteRenduTientSurUneLigne(t *testing.T) {
	rep := CompteRendu("CLE", "2.4.0", ResultatEchec, "ligne 1\nligne 2"+strings.Repeat("x", 400))
	l := strings.Split(rep, "\n")
	if len(l) != 8 || len([]rune(l[7])) > 240 {
		t.Errorf("%d lignes, motif de %d", len(l), len([]rune(l[len(l)-1])))
	}
}
