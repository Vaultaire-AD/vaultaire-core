package action

import (
	"os"
	"strings"
	"testing"
	"time"

	"vaultaire/core/gpo"
)

// Une GPO modifiée dit quand elle sera appliquée — TO-DO 86.

func TestLaPriseEnCompteDependDeLaPortee(t *testing.T) {
	ancienne := cadenceDesGPO
	t.Cleanup(func() { cadenceDesGPO = ancienne })
	cadenceDesGPO = func() time.Duration { return 90 * time.Minute }

	machine := priseEnCompte(gpo.ScopeMachine, "base_postes")
	// Les deux gestes qui évitent d'attendre, un par façade (TO-DO 169), et
	// tous deux limités aux machines de CETTE GPO.
	for _, attendu := range []string{"prochain cycle", "1 h 30", "vlt gpo refresh --gpo base_postes", "Demander un cycle"} {
		if !strings.Contains(machine, attendu) {
			t.Errorf("portée machine : %q ne dit pas « %s »", machine, attendu)
		}
	}
	if strings.Contains(machine, "--all") {
		t.Errorf("portée machine : le message propose de faire travailler tout le parc : %q", machine)
	}
	compte := priseEnCompte(gpo.ScopeUser, "env_admins")
	if !strings.Contains(compte, "prochaine ouverture de session") || !strings.Contains(compte, "déjà ouverte ne change pas") {
		t.Errorf("portée utilisateur : %q", compte)
	}
	// « gpo refresh » ne rejoue pas la politique d'un compte : la proposer ici
	// ferait attendre un effet qui ne viendra pas.
	if strings.Contains(compte, "refresh") {
		t.Errorf("portée utilisateur : le message propose un rafraîchissement qui ne la concerne pas : %q", compte)
	}
}

func TestLaCadenceSeLit(t *testing.T) {
	cas := map[time.Duration]string{
		0:                 "une heure",
		15 * time.Minute:  "15 min",
		time.Hour:         "1 h",
		90 * time.Minute:  "1 h 30",
		24 * time.Hour:    "24 h",
		125 * time.Minute: "2 h 05",
	}
	for d, veut := range cas {
		if got := cadenceLisible(d); got != veut {
			t.Errorf("%s → %q, attendu %q", d, got, veut)
		}
	}
}

// Chaque écriture sur une GPO le dit. Par le texte : les actions lisent la
// base, et les jouer demanderait de la peupler.
func TestChaqueEcritureSurUneGPODitQuandElleSApplique(t *testing.T) {
	brut, err := os.ReadFile("actions_gpo.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(brut)
	for _, fonction := range []string{
		"func modifierGPO(", "func reglerModeDeriveGPO(", "func ajouterModuleGPO(",
		"func modifierModuleGPO(", "func supprimerModuleGPO(",
	} {
		debut := strings.Index(source, fonction)
		if debut < 0 {
			t.Errorf("%s introuvable dans actions_gpo.go", fonction)
			continue
		}
		fin := strings.Index(source[debut+1:], "\nfunc ")
		corps := source[debut:]
		if fin >= 0 {
			corps = source[debut : debut+1+fin]
		}
		if !strings.Contains(corps, "priseEnCompte(policy.Scope, nom)") {
			t.Errorf("%s) ne dit plus quand la modification atteindra le parc : devant un poste qui ne bouge pas, "+
				"rien ne distingue « pas encore » de « jamais »", strings.TrimSuffix(fonction, "("))
		}
	}
}
