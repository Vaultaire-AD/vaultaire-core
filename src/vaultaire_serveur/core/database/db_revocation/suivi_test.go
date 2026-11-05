package dbrevocation

import (
	"database/sql"
	"strings"
	"testing"

	"vaultaire/core/revocation"
)

// Le suivi d'un ordre, machine par machine — TO-DO 164. Tout ce qui se DÉCIDE
// — l'ordre des machines, les libellés, le décompte, le commentaire — est
// éprouvé ici, sans base : la ligne de commande et le portail n'en décident rien.

func cible(nom string, statut revocation.TargetStatus, remises int, detail string) TargetRecord {
	return TargetRecord{ComputeurID: nom, Status: statut, Attempts: remises, Detail: detail}
}

// Ce qui n'est pas réglé est en tête : c'est la question qu'on pose pendant un
// incident, et la réponse ne doit pas être sous vingt lignes « appliqué ».
func TestLesCiblesNonRegleesSontEnTete(t *testing.T) {
	cibles := []TargetRecord{
		cible("PC-05", revocation.StatusAcked, 1, "applied"),
		cible("PC-04", revocation.StatusLifted, 2, ""),
		cible("PC-03", revocation.StatusPending, 0, ""),
		cible("PC-06", revocation.StatusPending, 7, ""),
		cible("pc-02", revocation.StatusFailed, 3, "command_failed : 2 processus"),
		cible("PC-01", revocation.StatusAcked, 1, "already_absent"),
		cible("PC-07", revocation.StatusFailed, 3, "command_failed : 1 processus"),
	}
	TrierCibles(cibles)

	var noms []string
	for _, c := range cibles {
		noms = append(noms, c.ComputeurID)
	}
	// Échecs (par nom à remises égales, sans la casse), puis attentes — la plus
	// sollicitée d'abord : elle est là et ne répond pas —, puis levées, puis
	// appliquées.
	attendu := "pc-02,PC-07,PC-06,PC-03,PC-04,PC-01,PC-05"
	if got := strings.Join(noms, ","); got != attendu {
		t.Errorf("ordre des cibles :\n  obtenu  %s\n  attendu %s", got, attendu)
	}
}

func TestLeDecompteDitCeQuiNeVaPasDAbord(t *testing.T) {
	d := Compter([]TargetRecord{
		cible("a", revocation.StatusAcked, 1, "applied"),
		cible("b", revocation.StatusAcked, 1, "applied"),
		cible("c", revocation.StatusPending, 0, ""),
		cible("d", revocation.StatusFailed, 4, "x"),
		cible("e", revocation.StatusLifted, 1, ""),
	})
	if d.Total() != 5 || d.ResteAFaire() != 2 {
		t.Fatalf("décompte %+v : total %d, reste %d", d, d.Total(), d.ResteAFaire())
	}
	if got, attendu := d.Lisible(), "5 machine(s) : 1 en échec, 1 en attente, 1 levé(s) avant application, 2 appliqué(s)"; got != attendu {
		t.Errorf("décompte lisible :\n  obtenu  %s\n  attendu %s", got, attendu)
	}
	// Une cible levée n'est PAS un reste à faire : l'ordre ne lui sera plus remis.
	if r := Compter([]TargetRecord{cible("e", revocation.StatusLifted, 1, "")}).ResteAFaire(); r != 0 {
		t.Errorf("une cible levée est comptée comme restant à faire (%d)", r)
	}
	if got := Compter(nil).Lisible(); got != "aucune machine visée" {
		t.Errorf("décompte vide : %q", got)
	}
	if got := Compter([]TargetRecord{cible("a", revocation.StatusAcked, 1, "")}).Lisible(); strings.Contains(got, "en échec") || strings.Contains(got, "en attente") {
		t.Errorf("un ordre réglé annonce des échecs ou des attentes : %q", got)
	}
}

// « En attente » se départage : hors ligne depuis l'ordre, ou là et muette.
func TestLeCommentaireDepartageLesAttentes(t *testing.T) {
	for _, c := range []struct {
		cible   TargetRecord
		attendu string
	}{
		{cible("a", revocation.StatusPending, 0, ""), "jamais remis : machine hors ligne depuis l'ordre"},
		{cible("a", revocation.StatusPending, 6, ""), "remis 6 fois, aucune réponse de la machine"},
		{cible("a", revocation.StatusFailed, 3, " command_failed : 2 processus survivent "), "command_failed : 2 processus survivent"},
		{cible("a", revocation.StatusFailed, 3, ""), "échec signalé sans motif"},
		{cible("a", revocation.StatusAcked, 1, "applied"), "ordre appliqué sur la machine"},
		{cible("a", revocation.StatusAcked, 1, "already_absent"), "aucun compte local de ce nom sur la machine"},
		{cible("a", revocation.StatusAcked, 1, "not_applicable"), "sans objet sur cette machine"},
		{cible("a", revocation.StatusAcked, 1, "autre chose"), "autre chose"},
	} {
		if got := c.cible.Commentaire(); got != c.attendu {
			t.Errorf("%s, %d remise(s), détail %q : commentaire %q, attendu %q",
				c.cible.Status, c.cible.Attempts, c.cible.Detail, got, c.attendu)
		}
	}
	levee := cible("a", revocation.StatusLifted, 2, "command_failed : ancien échec").Commentaire()
	if !strings.Contains(levee, "ne lui sera plus remis") || strings.Contains(levee, "command_failed") {
		t.Errorf("une cible levée garde le motif d'un échec périmé, ou ne dit pas qu'elle ne sera plus remise : %q", levee)
	}
}

func TestLesEtatsOntUnLibelleEtLeveNEstPasEnAttente(t *testing.T) {
	vus := map[string]bool{}
	for _, s := range []revocation.TargetStatus{
		revocation.StatusPending, revocation.StatusFailed, revocation.StatusAcked, revocation.StatusLifted,
	} {
		l := s.Libelle()
		if l == "" || l == string(s) {
			t.Errorf("l'état %q n'a pas de libellé : il s'afficherait sous son code", s)
		}
		if vus[l] {
			t.Errorf("deux états partagent le libellé %q", l)
		}
		vus[l] = true
	}
	if l := revocation.StatusLifted.Libelle(); strings.Contains(l, "attente") {
		t.Errorf("une cible levée s'affiche %q : on chercherait une machine qui n'a rien à faire", l)
	}
}

func TestLaDureeEstALaSecondePresSousLaMinute(t *testing.T) {
	for secondes, attendu := range map[int64]string{
		-3: "à l'instant", 0: "à l'instant", 4: "à l'instant",
		5: "il y a 5 s", 59: "il y a 59 s",
		60: "il y a 1 min", 3599: "il y a 59 min",
		3600: "il y a 1 h", 48*3600 - 1: "il y a 47 h",
		48 * 3600: "il y a 2 j",
	} {
		if got := DureeLisible(secondes); got != attendu {
			t.Errorf("DureeLisible(%d) = %q, attendu %q", secondes, got, attendu)
		}
	}
	if got := (TargetRecord{}).Echange(); got != "—" {
		t.Errorf("aucun échange : %q, attendu un tiret — pas un âge inventé", got)
	}
	if got := (TargetRecord{DepuisLeDernier: sql.NullInt64{Int64: 12, Valid: true}}).Echange(); got != "il y a 12 s" {
		t.Errorf("échange il y a 12 s rendu %q", got)
	}
}
