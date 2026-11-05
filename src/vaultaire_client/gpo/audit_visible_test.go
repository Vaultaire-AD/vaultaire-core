package gpo

import (
	"os"
	"strings"
	"testing"
)

// Audit et enforce se distinguent — TO-DO 86.
//
// La recette du 24/09 disait : « le mode audit ne produit pas de différence
// visible ». Le banc du 07/10 a montré pourquoi, en scope machine : après un
// écart, une machine en enforce le corrige dans le cycle, mais « gpo status »
// affichait « 1 écart(s) » jusqu'au cycle suivant — comme une machine en audit,
// qui ne corrige rien. Deux choses le ferment : le constat après correction
// (cycle.go), et la mention portée par l'écart qu'on ne corrigera pas.

func etatAvecModes(modes map[string]string) *ScopeState {
	return &ScopeState{Modes: modes}
}

func TestSeulUnEcartToutEnAuditEstMarqueNonCorrige(t *testing.T) {
	etat := etatAvecModes(map[string]string{
		"file_deploy:/etc/a":   string(DriftAudit),
		"file_deploy:/etc/b":   string(DriftEnforce),
		"user_env:EDITOR":      string(DriftAudit),
		"user_env:HTTPS_PROXY": string(DriftEnforce),
		"sysctl:vm.swappiness": string(DriftAudit),
	})
	rapport := DriftReport{Items: []DriftItem{
		{Path: "/etc/a", StateKey: "file_deploy:/etc/a", Kind: DriftModified},
		{Path: "/etc/b", StateKey: "file_deploy:/etc/b", Kind: DriftModified},
		// Un fichier que deux modules écrivent, l'un en audit, l'autre en
		// enforce : le second le réécrira. L'écart SERA corrigé.
		{Path: "/home/a/.vaultaire_env", StateKey: "user_env:EDITOR", Kind: DriftModified,
			Coproprietaires: []string{"user_env:HTTPS_PROXY"}},
		// Un module dont l'état ne dit rien : enforce, le mode par défaut.
		{Path: "/etc/c", StateKey: "file_deploy:/etc/c", Kind: DriftMissing},
		// Une incertitude ne fait rien rejouer, quel que soit le mode : la dire
		// « non corrigée pour cause d'audit » inventerait une cause.
		{Path: "vm.swappiness", StateKey: "sysctl:vm.swappiness", Kind: DriftUnverifiable},
		// Un écart sans module identifié : on ne sait pas, donc on ne dit rien.
		{Path: "/etc/d", StateKey: "", Kind: DriftModified},
	}}
	marquerLesNonCorriges(etat, &rapport)

	veut := []bool{true, false, false, false, false, false}
	for i, item := range rapport.Items {
		if item.NonCorrige != veut[i] {
			t.Errorf("%s (%s) : NonCorrige=%v, attendu %v", item.Path, item.Kind, item.NonCorrige, veut[i])
		}
	}

	// Sans état, rien n'est marqué — et rien ne panique.
	sansEtat := DriftReport{Items: []DriftItem{{Path: "/etc/a", StateKey: "file_deploy:/etc/a"}}}
	marquerLesNonCorriges(nil, &sansEtat)
	if sansEtat.Items[0].NonCorrige {
		t.Error("un écart est dit non corrigé sans qu'aucun état ne le dise en audit")
	}
}

func TestLeRapportDitCeQuiNeSeraPasCorrige(t *testing.T) {
	senderMu.Lock()
	ancien, ancienID := sender, clientID
	senderMu.Unlock()
	t.Cleanup(func() {
		senderMu.Lock()
		sender, clientID = ancien, ancienID
		senderMu.Unlock()
	})

	var trame string
	Configure(func(t string) { trame = t }, "PC-01")

	long := strings.Repeat("x", 400)
	err := SendDriftReport("cle", DriftReport{Scope: ScopeMachine, Checked: 3, Items: []DriftItem{
		{Path: "/etc/a", StateKey: "file_deploy:/etc/a", Kind: DriftModified, Detail: "contenu modifie", NonCorrige: true},
		{Path: "/etc/b", StateKey: "file_deploy:/etc/b", Kind: DriftModified, Detail: "contenu modifie"},
		{Path: "/etc/c", StateKey: "file_deploy:/etc/c", Kind: DriftModified, Detail: long, NonCorrige: true},
	}})
	if err != nil {
		t.Fatal(err)
	}

	var a, b, c string
	for _, ligne := range strings.Split(trame, "\n") {
		switch {
		case strings.HasPrefix(ligne, "file_deploy:/etc/a|"):
			a = ligne
		case strings.HasPrefix(ligne, "file_deploy:/etc/b|"):
			b = ligne
		case strings.HasPrefix(ligne, "file_deploy:/etc/c|"):
			c = ligne
		}
	}
	if a != "file_deploy:/etc/a|modified|/etc/a|[audit : signale, non corrige] contenu modifie" {
		t.Errorf("écart en audit : %q", a)
	}
	if b != "file_deploy:/etc/b|modified|/etc/b|contenu modifie" {
		t.Errorf("écart en enforce : %q — il ne doit rien porter, il sera corrigé", b)
	}
	// Le détail est tronqué à l'envoi : la mention doit être de ce qui survit.
	if !strings.Contains(c, "|"+strings.TrimSpace(MentionAudit)) {
		t.Errorf("la mention d'audit a été emportée par la troncature : %q", c)
	}
	// Quatre champs, pas un de plus : la mention ne doit pas introduire de
	// séparateur, le core lirait un champ pour un autre.
	for _, ligne := range []string{a, b, c} {
		if n := strings.Count(ligne, "|"); n != 3 {
			t.Errorf("%d séparateur(s) dans %q, attendu 3", n, ligne)
		}
	}
}

// Le branchement : en scope machine comme en scope utilisateur, le cycle qui
// vient de corriger ou de poser dit au core ce qu'il en est.
//
// Par le texte : jouer runMachineCycleWith demande un core qui réponde, et le
// test n'existerait pas. Ce qui est tenu ici, c'est que le constat reste appelé
// APRÈS le cycle, et pour la portée machine.
func TestLeCycleMachineConstateApresAvoirCorrige(t *testing.T) {
	brut, err := os.ReadFile("cycle.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(brut)
	debut := strings.Index(source, "func runMachineCycleWith(")
	fin := strings.Index(source, "func waitForSessionKey(")
	if debut < 0 || fin < debut {
		t.Fatal("runMachineCycleWith introuvable dans cycle.go")
	}
	corps := source[debut:fin]

	scan := strings.Index(corps, "corriges := scanMachineDrift(sessionKey)")
	cycle := strings.Index(corps, "RunMachineCycle(sessionKey)")
	constat := strings.Index(corps, "constaterApresApplication(sessionKey, ScopeMachine, \"\")")
	if scan < 0 || cycle < 0 || constat < 0 {
		t.Fatalf("scan=%d cycle=%d constat=%d : le cycle machine ne constate plus après avoir corrigé — "+
			"une machine en enforce affichera « N écart(s) » une cadence entière, comme une machine en audit",
			scan, cycle, constat)
	}
	if !(scan < cycle && cycle < constat) {
		t.Fatal("ordre attendu : scan, cycle, constat. Constater avant le cycle, c'est constater l'écart qu'on va corriger.")
	}
	if !strings.Contains(corps, "corriges > 0 || rapport.Counts()[ResultApplied] > 0") {
		t.Error("le constat n'est plus conditionné à une correction ou à une application : " +
			"il partirait à chaque cycle, ou jamais")
	}
}
