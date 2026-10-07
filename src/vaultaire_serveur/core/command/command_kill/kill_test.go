package commandkill

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/revocation"
	revocationmanager "vaultaire/ducky-network/revocation_manager"
)

// TO-DO 133 — ce que la commande AFFIRME.
//
// L'aide de `kill -h` disait, sous « ce que fait le mode par défaut » : « ses
// sessions ouvertes sont fermées immédiatement ». C'était faux, et c'est
// l'endroit où un exploitant va chercher la vérité pendant un incident. Ces
// tests gardent les phrases, pas le code : une aide qui promet plus que ce que
// l'ordre fait est un défaut au même titre qu'un ordre qui ne fait rien.

func TestLAideDitCeQuiEstCoupeEtCeQuiNeLEstPasEncore(t *testing.T) {
	aide := helpText()

	for _, attendu := range []string{
		"verrouillé, PUIS",       // l'ordre des deux gestes
		"détaché d'un terminal",  // la décision : tmux et nohup tombent aussi
		"session ouverte",        // les cibles ne sont plus les seuls groupes
		"HORS LIGNE",             // ce qui n'est PAS immédiat
		"toutes les dix minutes", // le rappel du point 134
		// TO-DO 49 : le core rejoue lui-même, et ne renonce pas.
		"rejoué par le",
		"sans jamais renoncer",
		// Une levée range le verrouillage que la machine n'avait pas appliqué.
		"ne recevront que la levée",
	} {
		if !strings.Contains(aide, attendu) {
			t.Errorf("l'aide ne dit plus %q", attendu)
		}
	}

	// La phrase d'origine, sans réserve : elle ne doit pas revenir. « Fermées
	// immédiatement » ne vaut que pour les sessions que le serveur tient.
	if strings.Contains(aide, "ses sessions ouvertes sont fermées immédiatement") {
		t.Error("l'aide affirme de nouveau que les sessions ouvertes sont fermees immediatement, " +
			"sans dire lesquelles ni sur quelles machines")
	}
}

func TestLeCompteRenduNeConfondPasRemisEtApplique(t *testing.T) {
	rendu := formatOutcome(revocationmanager.Outcome{
		OrderID: 12, Mode: revocation.ModeSoft, Username: "alice",
		TargetCount: 5, PushedNow: 3, SessionsKilled: 2,
		MachinesEnSession: 2, HorsGroupes: 1,
	})

	for _, attendu := range []string{
		"Sessions Vaultaire fermées (portail, Ducky) : 2",
		"Machines visées : 5 — dont 2 où une session du compte est ouverte",
		"1 visée(s) pour cette seule raison",
		"Ordre remis immédiatement : 3",
		"En attente (machines hors ligne) : 2",
		"kill -u alice --unlock",
	} {
		if !strings.Contains(rendu, attendu) {
			t.Errorf("le compte rendu ne porte pas %q :\n%s", attendu, rendu)
		}
	}
	for _, interdit := range []string{"Appliqué immédiatement", "  Sessions fermées :"} {
		if strings.Contains(rendu, interdit) {
			t.Errorf("le compte rendu dit encore %q : le core ne sait pas, a cet instant, "+
				"ce que les postes ont applique", interdit)
		}
	}
}

// Un déverrouillage ne coupe rien : le compte rendu ne doit pas le laisser croire.
func TestLeDeverrouillageNAnnonceAucuneCoupure(t *testing.T) {
	rendu := formatOutcome(revocationmanager.Outcome{
		OrderID: 13, Mode: revocation.ModeUnlock, Username: "alice", TargetCount: 2, PushedNow: 2,
	})
	if strings.Contains(rendu, "tue ses processus") {
		t.Errorf("un deverrouillage annonce une coupure :\n%s", rendu)
	}
}

// --- TO-DO 164 : kill -u <compte> --status ---------------------------------

func suiviDEssai() dbrevocation.Suivi {
	cible := func(nom string, s revocation.TargetStatus, remises int, depuis int64, detail string) dbrevocation.TargetRecord {
		c := dbrevocation.TargetRecord{ComputeurID: nom, Status: s, Attempts: remises, Detail: detail}
		if depuis >= 0 {
			c.DepuisLeDernier = sql.NullInt64{Int64: depuis, Valid: true}
		}
		return c
	}
	return dbrevocation.Suivi{
		Username: "bob.durand", Verrouille: true, PlusAnciens: 2,
		Ordres: []dbrevocation.OrdreSuivi{{
			Record: dbrevocation.Record{
				ID: 12, Username: "bob.durand", Mode: revocation.ModeSoft, Reason: revocation.ReasonCompromised,
				IssuedBy: "admin", IssuedAt: time.Date(2026, 10, 7, 16, 2, 3, 0, time.UTC), Total: 5, Pending: 2,
			},
			Masquees: 1,
			Cibles: []dbrevocation.TargetRecord{
				cible("PC-07", revocation.StatusFailed, 4, 12, "command_failed : 2 processus\nsurvivent"),
				cible("PC-03", revocation.StatusPending, 0, -1, ""),
				cible("PC-04", revocation.StatusLifted, 2, 600, ""),
				cible("PC-01", revocation.StatusAcked, 1, 200, "applied"),
			},
		}},
	}
}

// La question d'un incident — « où ce compte travaille-t-il encore ? » — a sa
// réponse dans la commande : une ligne par machine, et la phrase qui conclut.
func TestLeSuiviDitOuEnEstChaqueMachine(t *testing.T) {
	rendu := rendreSuivi(suiviDEssai(), "1 ordre(s) détaillé(s) pour bob.durand.")

	for _, attendu := range []string{
		"Compte bob.durand — VERROUILLÉ",
		"Ordre 12 — verrouillage du compte (compte compromis), par admin le 2026-10-07 16:02:03",
		"4 machine(s) : 1 en échec, 1 en attente, 1 levé(s) avant application, 1 appliqué(s)",
		"1 autre(s) machine(s) visée(s) sont hors de votre périmètre",
		"MACHINE", "ÉTAT", "REMISES", "DERNIER ÉCHANGE", "DÉTAIL",
		"il y a 12 s",
		"command_failed : 2 processus survivent", // le retour à la ligne de l'agent ne casse pas le tableau
		"jamais remis : machine hors ligne depuis l'ordre",
		"levé avant application",
		"ordre appliqué sur la machine",
		"2 ordre(s) plus ancien(s) ne sont pas détaillés",
		"L'ordre 12 n'est PAS appliqué sur 2 machine(s)",
	} {
		if !strings.Contains(rendu, attendu) {
			t.Errorf("le suivi ne dit pas %q :\n%s", attendu, rendu)
		}
	}
	// Une ligne par machine, dans l'ordre reçu : l'échec en tête.
	if strings.Index(rendu, "PC-07") > strings.Index(rendu, "PC-01") {
		t.Errorf("la machine en échec n'est pas avant celle qui a appliqué :\n%s", rendu)
	}
	for _, machine := range []string{"PC-07", "PC-03", "PC-04", "PC-01"} {
		if n := strings.Count(rendu, machine); n != 1 {
			t.Errorf("%s figure %d fois", machine, n)
		}
	}
}

func TestLeSuiviDUnOrdreRegleLeDit(t *testing.T) {
	s := suiviDEssai()
	s.Verrouille, s.PlusAnciens = false, 0
	s.Ordres[0].Masquees = 0
	s.Ordres[0].Cibles = s.Ordres[0].Cibles[3:] // seule la machine qui a appliqué
	rendu := rendreSuivi(s, "")
	if !strings.Contains(rendu, "aucun verrouillage en vigueur") || !strings.Contains(rendu, "L'ordre 12 est réglé sur toutes les machines visées.") {
		t.Errorf("un ordre réglé ne se lit pas comme tel :\n%s", rendu)
	}
	if strings.Contains(rendu, "n'est PAS appliqué") {
		t.Errorf("un ordre réglé annonce des machines restantes :\n%s", rendu)
	}

	// Des machines masquées : on ne peut PAS conclure que tout est réglé.
	s.Ordres[0].Masquees = 2
	if rendu := rendreSuivi(s, ""); strings.Contains(rendu, "réglé sur toutes les machines") {
		t.Errorf("l'ordre est dit réglé partout alors que deux machines ne sont pas montrées :\n%s", rendu)
	}
}

func TestSansOrdreLeSuiviRendLeMessageDeLAction(t *testing.T) {
	if got := rendreSuivi(dbrevocation.Suivi{Username: "x"}, "Aucun ordre de révocation pour x."); got != "Aucun ordre de révocation pour x." {
		t.Errorf("suivi vide : %q", got)
	}
}

// --status est une LECTURE et ne se combine avec rien : sur la commande la
// plus destructrice du produit, « kill -u bob --hard --status » ne doit pas
// pouvoir se lire « supprime, puis dis-moi ».
func TestStatusNeSeCombineAvecAucuneAutreOption(t *testing.T) {
	for _, args := range [][]string{
		{"-u", "bob", "--hard", "--status"},
		{"-u", "bob", "--status", "--hard"},
		{"-u", "bob", "--status", "--unlock"},
		{"-u", "bob", "--reason", "offboarding", "--status"},
	} {
		// Sans base ni registre : si la commande déclenchait quoi que ce soit,
		// elle n'atteindrait pas ce message.
		rendu := Kill_Command(args, nil, "admin")
		if !strings.Contains(rendu, "--status est une lecture") || !strings.Contains(rendu, "rien n'a été déclenché") {
			t.Errorf("kill %s : %q — attendu un refus qui dit que rien n'est parti", strings.Join(args, " "), rendu)
		}
	}
}

func TestLAideDitCommentSuivreUnOrdre(t *testing.T) {
	aide := helpText()
	for _, attendu := range []string{"--status", "machine par machine", "ne déclenche rien", "read:status:user"} {
		if !strings.Contains(aide, attendu) {
			t.Errorf("l'aide ne dit pas %q", attendu)
		}
	}
	// Le compte rendu d'un ordre renvoie à la commande, plus au journal.
	rendu := formatOutcome(revocationmanager.Outcome{
		OrderID: 12, Mode: revocation.ModeSoft, Username: "alice", TargetCount: 2, PushedNow: 2,
	})
	if !strings.Contains(rendu, "kill -u alice --status") {
		t.Errorf("le compte rendu ne dit pas où lire la suite :\n%s", rendu)
	}
}

// Un ordre ancien et réglé tient en une ligne ; un ordre ancien qui ne l'est
// pas garde son tableau.
func TestLesOrdresAnciensReglesNeNoientPasLeSuivi(t *testing.T) {
	s := suiviDEssai()
	regle := dbrevocation.OrdreSuivi{
		Record: dbrevocation.Record{ID: 9, Mode: revocation.ModeUnlock, Reason: revocation.ReasonAdminRequest, IssuedBy: "admin"},
		Cibles: []dbrevocation.TargetRecord{{ComputeurID: "PC-ANCIEN-REGLE", Status: revocation.StatusAcked, Attempts: 1, Detail: "applied"}},
	}
	enEchec := dbrevocation.OrdreSuivi{
		Record: dbrevocation.Record{ID: 7, Mode: revocation.ModeSoft, Reason: revocation.ReasonCompromised, IssuedBy: "admin"},
		Cibles: []dbrevocation.TargetRecord{{ComputeurID: "PC-ANCIEN-ECHEC", Status: revocation.StatusFailed, Attempts: 9, Detail: "x"}},
	}
	s.Ordres = append(s.Ordres, regle, enEchec)

	rendu := rendreSuivi(s, "")
	if !strings.Contains(rendu, "Ordre 9 — levée du verrouillage") || !strings.Contains(rendu, "1 machine(s) : 1 appliqué(s)") {
		t.Errorf("l'ordre ancien réglé a disparu, ou son décompte :\n%s", rendu)
	}
	if strings.Contains(rendu, "PC-ANCIEN-REGLE") {
		t.Errorf("un ordre ancien et réglé déroule son tableau de machines :\n%s", rendu)
	}
	if !strings.Contains(rendu, "PC-ANCIEN-ECHEC") {
		t.Errorf("un ordre ancien NON réglé a perdu son tableau :\n%s", rendu)
	}
}
