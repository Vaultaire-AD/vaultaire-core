package logs

import (
	"sync"
	"testing"

	"vaultaire/core/storage"
)

// La sortie branchée — ce qui alimente le journal centralisé en base.
//
// # Ce que ces tests gardent
//
// Une ligne qui n'atteint pas la sortie n'apparaît pas dans le journal commun
// des cores, et rien ne le signale : on la cherche sur le portail, on ne la
// trouve pas, et on conclut qu'elle n'a pas été écrite. Et une ligne DEBUG qui
// passerait le filtre du mode debug partirait en base sans que personne l'ait
// demandé.

// capturer branche une sortie qui garde ce qu'elle reçoit, et la retire à la
// fin du test.
func capturer(t *testing.T) *[]LogEntry {
	t.Helper()
	var mu sync.Mutex
	recues := []LogEntry{}
	BrancherSortie(func(e LogEntry) {
		mu.Lock()
		recues = append(recues, e)
		mu.Unlock()
	})
	t.Cleanup(func() { BrancherSortie(nil) })
	return &recues
}

func TestChaqueLigneAtteintLaSortieBranchee(t *testing.T) {
	recues := capturer(t)

	Write_LogCode("WARNING", CodeAuthFailed, "tentative refusée")
	Write_LogCodeMeta("ERROR", CodeDBQuery, "requête échouée", WithMeta("req-1", "42"))

	if len(*recues) != 2 {
		t.Fatalf("%d entrée(s) reçue(s), attendu 2 : une ligne émise manquerait "+
			"au journal commun des cores", len(*recues))
	}
	e := (*recues)[1]
	if e.Level != "ERROR" || e.Code != CodeDBQuery || e.Message != "requête échouée" {
		t.Errorf("entrée transmise = %+v : ce n'est pas celle qui a été émise", e)
	}
	if e.RequestID != "req-1" || e.UserID != "42" {
		t.Errorf("métadonnées perdues en route : %+v", e)
	}
	if e.Hostname != NomDuCore() || e.Hostname == "" {
		t.Errorf("core émetteur = %q, attendu %q : une ligne centralisée sans "+
			"auteur ne dit pas quel core l'a écrite", e.Hostname, NomDuCore())
	}
}

func TestUnDebugFiltreNAtteintPasLaSortie(t *testing.T) {
	ancien := storage.Debug
	storage.Debug = false
	t.Cleanup(func() { storage.Debug = ancien })

	recues := capturer(t)
	Write_Log("DEBUG", "détail d'un échange")

	if len(*recues) != 0 {
		t.Fatalf("une ligne DEBUG hors mode debug a atteint la sortie : elle " +
			"partirait en base sans que personne l'ait demandée")
	}
}

func TestSansSortieRienNeCasse(t *testing.T) {
	BrancherSortie(nil)
	// Aucune assertion : le test échoue s'il panique. C'est l'état de tout
	// core avant le branchement, et de tout binaire de test.
	Write_Log("INFO", "ligne sans sortie branchée")
}

func TestLaMemoireRendLaPlusRecenteEnPremier(t *testing.T) {
	ClearLogs()
	Write_Log("INFO", "première")
	Write_Log("INFO", "seconde")

	e := EntreesEnMemoire()
	if len(e) != 2 || e[0].Message != "seconde" || e[1].Message != "première" {
		t.Fatalf("ordre rendu = %v : le repli du portail montrerait le plus "+
			"ancien d'abord, et la page utile serait la dernière", e)
	}
}
