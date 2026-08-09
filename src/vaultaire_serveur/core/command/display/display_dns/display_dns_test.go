package displaydns

import (
	"database/sql"
	"strings"
	"testing"

	"vaultaire/core/command/display"
	dnsstorage "vaultaire/core/dns/DNS_Storage"
)

// TestLesEnregistrementsSontDansLaSortie est le test du défaut d'origine.
//
// La boucle d'affichage appelait `fmt.Println(w, "%-25s ...", ...)` au lieu de
// `fmt.Fprintf`. Le writer était donc un simple argument à imprimer, la chaîne
// de format partait telle quelle, et le tout allait sur la sortie standard —
// pas dans la valeur rendue.
//
// La fonction rendait ainsi un tableau vide alors que la zone contenait des
// enregistrements. Ce test échoue sur ce code : il exige que les données
// figurent dans ce que la fonction RETOURNE.
func TestLesEnregistrementsSontDansLaSortie(t *testing.T) {
	records := []dnsstorage.ZoneRecord{
		{ID: 1, Name: "www", Type: "A", TTL: 3600, Data: "10.0.0.1"},
		{ID: 2, Name: "mail", Type: "MX", TTL: 300, Data: "mx.exemple.fr",
			Priority: sql.NullInt64{Int64: 10, Valid: true}},
	}

	out := DisplayZoneRecords(records, "exemple.fr")

	for _, attendu := range []string{"www", "10.0.0.1", "mail", "mx.exemple.fr", "3600", "MX"} {
		if !strings.Contains(out, attendu) {
			t.Fatalf("%q absent de la sortie — les données ne sont pas rendues :\n%s", attendu, out)
		}
	}
	// Le format ne doit jamais apparaître littéralement.
	if strings.Contains(out, "%-") {
		t.Fatalf("une chaîne de format est imprimée telle quelle :\n%s", out)
	}
}

// TestPrioriteNulleEtPrioriteZeroDifferent.
//
// `Priority` est un sql.NullInt64. Un enregistrement A n'a pas de priorité —
// la colonne vaut NULL — tandis qu'un MX de priorité 0 en a une, et c'est la
// plus haute. Les confondre afficherait « 0 » sur tous les A, ce qui se lit
// comme « prioritaire » au lieu de « sans objet ».
func TestPrioriteNulleEtPrioriteZeroDifferent(t *testing.T) {
	absente := priorite(dnsstorage.ZoneRecord{})
	zero := priorite(dnsstorage.ZoneRecord{Priority: sql.NullInt64{Int64: 0, Valid: true}})

	if absente == zero {
		t.Fatalf("priorité absente et priorité 0 rendues pareil (%q) — "+
			"0 est une priorité MX valide, et la plus haute", absente)
	}
	if zero != "0" {
		t.Errorf("priorité 0 rendue %q", zero)
	}
	if absente != "—" {
		t.Errorf("priorité absente rendue %q", absente)
	}
}

// TestColonnesAligneesSurLesEnregistrements : les valeurs d'une colonne
// démarrent toutes au même caractère, quelle que soit la longueur des
// précédentes.
func TestColonnesAligneesSurLesEnregistrements(t *testing.T) {
	records := []dnsstorage.ZoneRecord{
		{ID: 1, Name: "a", Type: "A", TTL: 60, Data: "10.0.0.1"},
		{ID: 2, Name: "un-nom-de-machine-tres-long", Type: "CNAME", TTL: 60, Data: "a.exemple.fr"},
	}

	lignes := strings.Split(strings.TrimRight(DisplayZoneRecords(records, "z"), "\n"), "\n")

	// Les deux dernières lignes sont les enregistrements.
	l1, l2 := lignes[len(lignes)-2], lignes[len(lignes)-1]
	if display.LargeurVisible(l1) == 0 || display.LargeurVisible(l2) == 0 {
		t.Fatalf("lignes vides :\n%s", strings.Join(lignes, "\n"))
	}
	// La colonne Données démarre au même endroit sur les deux lignes.
	//
	// Les positions sont vérifiées avant découpe : sur un affichage défaillant
	// la valeur est absente, strings.Index rend -1, et une tranche négative
	// ferait paniquer le test au lieu de le faire échouer avec un diagnostic.
	i1, i2 := strings.Index(l1, "10.0.0.1"), strings.Index(l2, "a.exemple.fr")
	if i1 < 0 || i2 < 0 {
		t.Fatalf("les données ne figurent pas dans les lignes rendues :\n%s",
			strings.Join(lignes, "\n"))
	}
	p1 := display.LargeurVisible(l1[:i1])
	p2 := display.LargeurVisible(l2[:i2])
	if p1 != p2 {
		t.Fatalf("la colonne Données démarre en %d puis %d :\n%s", p1, p2,
			strings.Join(lignes, "\n"))
	}
}

// TestZoneVideLeDitClairement : un tableau à en-têtes sans ligne se lit comme
// un défaut d'affichage ; une phrase se lit comme une information.
func TestZoneVideLeDitClairement(t *testing.T) {
	out := DisplayZoneRecords(nil, "exemple.fr")
	if !strings.Contains(out, "aucun enregistrement") {
		t.Errorf("zone vide rendue %q", out)
	}
	if !strings.Contains(out, "exemple.fr") {
		t.Errorf("le nom de la zone manque : %q", out)
	}
}

// TestZonesTriees : la base ne garantit aucun ordre. Deux appels affichant les
// mêmes zones dans un ordre différent laissent croire à un changement.
func TestZonesTriees(t *testing.T) {
	zones := []dnsstorage.Zone{
		{ZoneName: "zeta.fr", TableName: "dns_zeta"},
		{ZoneName: "alpha.fr", TableName: "dns_alpha"},
	}
	out := DisplayAllZones(zones)
	if strings.Index(out, "alpha.fr") > strings.Index(out, "zeta.fr") {
		t.Fatalf("zones non triées :\n%s", out)
	}
}

func TestAucuneZone(t *testing.T) {
	if !strings.Contains(DisplayAllZones(nil), "Aucune zone") {
		t.Errorf("liste vide rendue %q", DisplayAllZones(nil))
	}
}
