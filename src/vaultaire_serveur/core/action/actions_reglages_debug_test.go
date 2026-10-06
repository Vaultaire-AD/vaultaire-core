package action

import (
	"strings"
	"testing"

	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Le réglage du détail du journal — TO-DO 145.
//
// # Ce que ces tests gardent
//
// Une saisie mal comprise ne règle RIEN. C'est le défaut que `update -debug`
// avait déjà eu : « ture » coupait le debug en annonçant une valeur invalide.
// Avec un réglage par sous-système, il y a deux champs où se tromper.

func detailDOrigine(t *testing.T) {
	t.Helper()
	ancien := storage.Debug
	storage.Debug = false
	for _, s := range logs.SousSystemes() {
		logs.LaisserDetail(s)
	}
	t.Cleanup(func() {
		storage.Debug = ancien
		for _, s := range logs.SousSystemes() {
			logs.LaisserDetail(s)
		}
	})
}

var quelquun = Appelant{Username: "alice"}

func TestUnSousSystemeSeRegle(t *testing.T) {
	detailDOrigine(t)

	res, err := reglerDebug(quelquun, Params{"sous_systeme": "LDAP", "niveau": "Trace"})
	if err != nil {
		t.Fatalf("réglage refusé : %v", err)
	}
	if d, propre := logs.DetailRegle(logs.SousLDAP); !propre || d != logs.DetailTrace {
		t.Fatalf("détail de ldap = %v (propre=%v), attendu trace", d, propre)
	}
	if storage.Debug {
		t.Error("le mode debug général a été touché par le réglage d'un sous-système")
	}
	// La réponse REND l'état : on relit ce qu'on vient de poser, là où on l'a posé.
	if !strings.Contains(res.Message, "ldap") || !strings.Contains(res.Message, "trace") {
		t.Errorf("la réponse ne rend pas l'état : %q", res.Message)
	}
}

func TestDefautRetireLeReglage(t *testing.T) {
	detailDOrigine(t)
	logs.ReglerDetail(logs.SousLDAP, logs.DetailCoupe)

	if _, err := reglerDebug(quelquun, Params{"sous_systeme": "ldap", "niveau": "defaut"}); err != nil {
		t.Fatal(err)
	}
	if _, propre := logs.DetailRegle(logs.SousLDAP); propre {
		t.Fatal("« defaut » n'a pas retiré le réglage propre du sous-système")
	}
}

// Sous-système inconnu, niveau inconnu, niveau absent : rien n'est réglé, et le
// refus dit ce qui est attendu.
func TestUneSaisieInconnueNeRegleRien(t *testing.T) {
	for nom, c := range map[string]struct {
		params  Params
		attendu string
	}{
		"sous-système mal orthographié": {Params{"sous_systeme": "ldpa", "niveau": "trace"}, "ldap, ducky, gpo, base"},
		"niveau mal orthographié":       {Params{"sous_systeme": "ldap", "niveau": "tarce"}, "off, debug, trace"},
		"niveau absent":                 {Params{"sous_systeme": "ldap"}, "niveau requis"},
	} {
		t.Run(nom, func(t *testing.T) {
			detailDOrigine(t)
			_, err := reglerDebug(quelquun, c.params)
			if err == nil || !strings.Contains(err.Error(), c.attendu) {
				t.Fatalf("err = %v : attendu un refus citant %q", err, c.attendu)
			}
			for _, s := range logs.SousSystemes() {
				if _, propre := logs.DetailRegle(s); propre {
					t.Errorf("%s a été réglé par une saisie refusée", s)
				}
			}
		})
	}
}

// Le réglage général reste ce qu'il était : `debug=true` ne règle aucun
// sous-système, et ne retire pas ceux qui le sont.
func TestLeReglageGeneralNeToucheAucunSousSysteme(t *testing.T) {
	detailDOrigine(t)
	logs.ReglerDetail(logs.SousLDAP, logs.DetailCoupe)

	if _, err := reglerDebug(quelquun, Params{"debug": "true"}); err != nil {
		t.Fatal(err)
	}
	if !storage.Debug {
		t.Fatal("le mode debug n'a pas été activé")
	}
	if d, propre := logs.DetailRegle(logs.SousLDAP); !propre || d != logs.DetailCoupe {
		t.Errorf("ldap = %v (propre=%v) : activer le debug général a rallumé l'annuaire "+
			"qu'on venait de couper — c'est exactement ce que le réglage sert à éviter", d, propre)
	}
}

// La lecture : l'état effectif ET le réglage propre, qui ne se lisent pas
// pareil — « ldap écrit en debug parce que le mode debug est actif » n'est pas
// « ldap est réglé à debug ».
func TestLEtatDistingueLeReglageDeLEffet(t *testing.T) {
	detailDOrigine(t)
	storage.Debug = true
	logs.ReglerDetail(logs.SousGPO, logs.DetailTrace)

	res, err := lireDebug(quelquun, Params{})
	if err != nil {
		t.Fatal(err)
	}
	etat, ok := res.Donnees.(EtatDuDebug)
	if !ok || !etat.Debug || len(etat.SousSystemes) != len(logs.SousSystemes()) {
		t.Fatalf("état rendu = %+v", res.Donnees)
	}
	par := map[string]DetailDeSousSysteme{}
	for _, s := range etat.SousSystemes {
		par[s.Nom] = s
	}
	if par["ldap"].Regle != "" || par["ldap"].Effectif != "debug" {
		t.Errorf("ldap = %+v : il suit le mode debug, sans réglage propre", par["ldap"])
	}
	if par["gpo"].Regle != "trace" || par["gpo"].Effectif != "trace" {
		t.Errorf("gpo = %+v, attendu réglé et effectif à trace", par["gpo"])
	}
	for _, attendu := range []string{"Mode debug : true", "suit le mode debug", "réglé à trace"} {
		if !strings.Contains(res.Message, attendu) {
			t.Errorf("le texte de l'état ne porte pas %q :\n%s", attendu, res.Message)
		}
	}
}

// Lire l'état ne le change pas. Une consultation n'écrit rien.
func TestLireNeRegleRien(t *testing.T) {
	detailDOrigine(t)
	if _, err := lireDebug(quelquun, Params{"debug": "true", "sous_systeme": "ldap", "niveau": "trace"}); err != nil {
		t.Fatal(err)
	}
	if storage.Debug || logs.UnDetailEstActif() {
		t.Fatal("la lecture de l'état a réglé quelque chose")
	}
}
