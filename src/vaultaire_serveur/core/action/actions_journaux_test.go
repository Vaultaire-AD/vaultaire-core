package action

import (
	"strings"
	"testing"
	"time"

	"vaultaire/core/database"
	dbjournaux "vaultaire/core/database/db_journaux"
	"vaultaire/core/logs"
)

// La consultation du journal commun, `log.list`.
//
// # Ce que ces tests gardent
//
//   - la lecture des paramètres, commune au portail et à `vlt logs` : une
//     saisie mal comprise doit être REFUSÉE en disant la forme attendue, pas
//     traduite en un filtre qui montrerait autre chose que ce qu'on a demandé ;
//   - le REPLI sur la mémoire du core quand la base ne répond pas, et surtout
//     qu'il se DISE : une page tirée d'un seul core, présentée comme le journal
//     commun, ferait conclure qu'il ne s'est rien passé sur les autres.

var instantDeReference = time.Date(2026, 9, 24, 15, 0, 0, 0, time.Local)

func TestLeNiveauEstUnSeuil(t *testing.T) {
	f, err := FiltreJournal(Params{"level": "warning"}, instantDeReference)
	if err != nil {
		t.Fatal(err)
	}
	if f.SeveriteMax != logs.SeverityWarning {
		t.Fatalf("seuil = %d, attendu %d (WARNING)", f.SeveriteMax, logs.SeverityWarning)
	}
	if f, _ := FiltreJournal(Params{}, instantDeReference); f.SeveriteMax >= 0 {
		t.Fatalf("sans niveau, seuil = %d : des lignes seraient écartées sans qu'on l'ait demandé", f.SeveriteMax)
	}
}

func TestUnNiveauInconnuEstRefuse(t *testing.T) {
	_, err := FiltreJournal(Params{"level": "WARNIGN"}, instantDeReference)
	if err == nil || !strings.Contains(err.Error(), "WARNING") {
		t.Fatalf("err = %v : une faute de frappe doit être refusée en citant les "+
			"niveaux connus, pas retomber sur INFO en silence", err)
	}
}

func TestLesInstantsRelatifsEtAbsolus(t *testing.T) {
	cas := []struct {
		saisie   string
		attendue time.Time
	}{
		{"2h", instantDeReference.Add(-2 * time.Hour)},
		{"30m", instantDeReference.Add(-30 * time.Minute)},
		{"3j", instantDeReference.Add(-72 * time.Hour)},
		{"3d", instantDeReference.Add(-72 * time.Hour)},
		{"2026-09-20", time.Date(2026, 9, 20, 0, 0, 0, 0, time.Local)},
		{"2026-09-20 08:15", time.Date(2026, 9, 20, 8, 15, 0, 0, time.Local)},
		// Ce que rend un champ datetime-local du navigateur.
		{"2026-09-20T08:15", time.Date(2026, 9, 20, 8, 15, 0, 0, time.Local)},
	}
	for _, c := range cas {
		f, err := FiltreJournal(Params{"since": c.saisie}, instantDeReference)
		if err != nil {
			t.Errorf("%q refusé : %v", c.saisie, err)
			continue
		}
		if !f.Depuis.Equal(c.attendue) {
			t.Errorf("%q lu comme %s, attendu %s", c.saisie, f.Depuis, c.attendue)
		}
	}
}

func TestUnInstantIllisibleEstRefuse(t *testing.T) {
	for _, s := range []string{"hier", "-2h", "0j", "24/09/2026"} {
		if _, err := FiltreJournal(Params{"since": s}, instantDeReference); err == nil {
			t.Errorf("%q accepté : il serait lu comme une date qu'on n'a pas voulue", s)
		}
	}
}

func TestUnePeriodeVideEstRefusee(t *testing.T) {
	_, err := FiltreJournal(Params{"since": "1h", "until": "2h"}, instantDeReference)
	if err == nil {
		t.Fatal("période dont la fin précède le début acceptée : la page serait " +
			"vide, et se lirait comme « rien ne s'est passé »")
	}
}

func TestLaPaginationSeLitEtSeBorne(t *testing.T) {
	f, err := FiltreJournal(Params{"page": "3", "per_page": "100000"}, instantDeReference)
	if err != nil {
		t.Fatal(err)
	}
	if f.Page != 3 || f.ParPage != dbjournaux.ParPageMax {
		t.Fatalf("page %d, %d par page", f.Page, f.ParPage)
	}
	if _, err := FiltreJournal(Params{"page": "0"}, instantDeReference); err == nil {
		t.Error("page 0 acceptée")
	}
}

func TestSansBaseLeJournalSeReplieEtLeDit(t *testing.T) {
	if database.GetDatabase() != nil {
		t.Skip("ce test éprouve le repli quand la base est absente ; une base est branchée")
	}
	logs.ClearLogs()
	logs.Write_LogCode("ERROR", logs.CodeDBConnection, "base injoignable")
	logs.Write_Log("INFO", "ligne ordinaire")

	res, err := listerJournal(Appelant{Username: "root"}, Params{"level": "ERROR"})
	if err != nil {
		t.Fatalf("le repli a échoué : %v — sans base, plus aucune façade ne "+
			"montrerait de journal, au moment où l'on en a le plus besoin", err)
	}
	vue, ok := res.Donnees.(JournalVue)
	if !ok {
		t.Fatalf("Donnees de type %T", res.Donnees)
	}
	if vue.Source != SourceMemoire || vue.Avertissement == "" {
		t.Fatalf("source %q, avertissement %q : une page tirée d'un seul core doit "+
			"le dire", vue.Source, vue.Avertissement)
	}
	if !strings.Contains(vue.Avertissement, logs.NomDuCore()) {
		t.Errorf("l'avertissement ne nomme pas le core qui répond : %q", vue.Avertissement)
	}
	if len(vue.Lignes) != 1 || vue.Lignes[0].Message != "base injoignable" {
		t.Fatalf("lignes = %+v : le filtre ne s'applique pas au repli", vue.Lignes)
	}
}
