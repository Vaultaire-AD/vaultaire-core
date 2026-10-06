package commandlogs

import (
	"strings"
	"testing"
	"time"

	"vaultaire/core/action"
	dbjournaux "vaultaire/core/database/db_journaux"
	"vaultaire/core/logs"
)

// `vlt logs`.
//
// # Ce que ces tests gardent
//
//   - une option mal tapée est refusée : ignorée, elle rendrait le journal
//     entier en laissant croire qu'il a été filtré ;
//   - un repli sur la mémoire d'un seul core se voit en tête de réponse ;
//   - la « suite » proposée reprend le filtre, sinon la page 2 serait celle
//     d'une autre question.

func TestUneOptionInconnueEstRefusee(t *testing.T) {
	if _, err := lireOptions([]string{"--sinec", "2h"}); err == nil {
		t.Fatal("« --sinec » accepté : le journal entier serait rendu comme s'il était filtré")
	}
	if _, err := lireOptions([]string{"--since"}); err == nil {
		t.Fatal("option sans valeur acceptée")
	}
}

func TestLesOptionsDeviennentLesParametresDeLAction(t *testing.T) {
	p, err := lireOptions([]string{"--level", "ERROR", "--core", "core-2",
		"--since", "2h", "--until", "1h", "--code", "VLT-DB001", "--page", "2", "--per-page", "10"})
	if err != nil {
		t.Fatal(err)
	}
	attendus := map[string]string{"level": "ERROR", "core": "core-2", "since": "2h",
		"until": "1h", "code": "VLT-DB001", "page": "2", "per_page": "10"}
	for k, v := range attendus {
		if p[k] != v {
			t.Errorf("paramètre %s = %q, attendu %q", k, p[k], v)
		}
	}
	// Les noms doivent être ceux que lit l'action : un nom de paramètre que
	// FiltreJournal ignore serait une option sans effet.
	if _, err := action.FiltreJournal(p, time.Now()); err != nil {
		t.Fatalf("l'action refuse ce que la commande produit : %v", err)
	}
}

func TestLeReplieEstAnnonceEnTete(t *testing.T) {
	vue := action.JournalVue{
		Source:        action.SourceMemoire,
		Avertissement: "journal commun illisible",
		Page:          dbjournaux.Page{Page: 1, ParPage: 50},
	}
	got := afficher(vue, nil)
	if !strings.HasPrefix(got, "⚠ journal commun illisible") {
		t.Fatalf("réponse = %q : une page d'un seul core se lirait comme le journal commun", got)
	}
}

func TestLaSuiteReprendLeFiltre(t *testing.T) {
	vue := action.JournalVue{
		Source: action.SourceBase,
		Page: dbjournaux.Page{Page: 2, ParPage: 1, Suivante: true, Lignes: []logs.LogEntry{
			{Timestamp: time.Now(), Level: "ERROR", Hostname: "core-1", Message: "m"},
		}},
	}
	got := afficher(vue, []string{"--level", "ERROR", "--page", "2"})
	if !strings.Contains(got, "Suite : logs --level ERROR --page 3") {
		t.Fatalf("réponse = %q : la suite doit garder le filtre et avancer d'une page", got)
	}
}
