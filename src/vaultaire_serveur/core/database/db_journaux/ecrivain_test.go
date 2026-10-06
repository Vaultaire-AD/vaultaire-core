package dbjournaux

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"vaultaire/core/logs"
)

// L'écrivain du journal commun.
//
// # Ce que ces tests gardent
//
// Trois promesses, dont aucune ne se voit en lisant le portail :
//
//   - une ligne émise atteint la base, y compris celles qui attendaient encore
//     quand le core s'arrête — ce sont souvent elles qui disent pourquoi ;
//   - une ligne qui n'atteint PAS la base est comptée et le trou est dit, sinon
//     il se lit comme une période calme ;
//   - l'appelant n'attend jamais : une base lente ne doit pas ralentir chaque
//     requête qui journalise.

// insertionsCapturees est une fonction d'insertion qui garde ce qu'elle reçoit.
type insertionsCapturees struct {
	mu    sync.Mutex
	lots  [][]logs.LogEntry
	echec error
}

func (c *insertionsCapturees) inserer(lot []logs.LogEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.echec != nil {
		return c.echec
	}
	// Une COPIE : l'écrivain réemploie son tableau de lot après l'appel.
	c.lots = append(c.lots, append([]logs.LogEntry(nil), lot...))
	return nil
}

func (c *insertionsCapturees) messages() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, l := range c.lots {
		for _, e := range l {
			out = append(out, e.Message)
		}
	}
	return out
}

func entree(niveau, message string) logs.LogEntry {
	sev, _ := logs.SeveriteDe(niveau)
	return logs.LogEntry{
		Timestamp: time.Now(), Severity: sev, Level: niveau,
		Message: message, Hostname: "core-test",
	}
}

func TestLesLignesEnAttenteSontEcritesALArret(t *testing.T) {
	c := &insertionsCapturees{}
	e := NouvelEcrivain(c.inserer)

	for i := 0; i < TailleLot+3; i++ {
		e.Recevoir(entree("INFO", "ligne"))
	}
	arret := make(chan struct{})
	close(arret)

	fini := make(chan struct{})
	go func() { e.Tourner(arret); close(fini) }()
	select {
	case <-fini:
	case <-time.After(5 * time.Second):
		t.Fatal("Tourner ne rend pas la main à l'arrêt : un core qu'on arrête resterait suspendu")
	}

	if got := len(c.messages()); got != TailleLot+3 {
		t.Fatalf("%d ligne(s) insérée(s) sur %d : les dernières lignes d'un core "+
			"qu'on arrête n'atteindraient pas le journal commun", got, TailleLot+3)
	}
	for _, l := range c.lots {
		if len(l) > TailleLot {
			t.Errorf("lot de %d lignes, au-delà de TailleLot (%d) : la requête "+
				"pourrait dépasser max_allowed_packet", len(l), TailleLot)
		}
	}
}

func TestLeDebugNeVaPasEnBase(t *testing.T) {
	c := &insertionsCapturees{}
	e := NouvelEcrivain(c.inserer)
	e.Recevoir(entree("DEBUG", "détail"))
	e.Recevoir(entree("INFO", "audit"))
	e.viderFile(nil)

	if m := c.messages(); len(m) != 1 || m[0] != "audit" {
		t.Fatalf("insérées = %v : le DEBUG a sa place sur la sortie standard, pas "+
			"dans une table que tous les cores remplissent", m)
	}
}

func TestUneFilePleineNeBloquePasEtCompte(t *testing.T) {
	e := NouvelEcrivain(func([]logs.LogEntry) error { return nil })

	fini := make(chan struct{})
	go func() {
		for i := 0; i < CapaciteFile+5; i++ {
			e.Recevoir(entree("INFO", "x"))
		}
		close(fini)
	}()
	select {
	case <-fini:
	case <-time.After(5 * time.Second):
		t.Fatal("Recevoir bloque sur une file pleine : chaque requête qui " +
			"journalise attendrait la base")
	}
	if n := e.perdues.Load(); n != 5 {
		t.Fatalf("%d perte(s) comptée(s), attendu 5 : un trou dans le journal "+
			"commun passerait pour une période calme", n)
	}
}

func TestUnLotRefuseEstCompteEtSignale(t *testing.T) {
	logs.ClearLogs()
	c := &insertionsCapturees{echec: errors.New("base arrêtée")}
	e := NouvelEcrivain(c.inserer)

	e.traiter([]logs.LogEntry{entree("INFO", "a"), entree("ERROR", "b")})
	if n := e.perdues.Load(); n != 2 {
		t.Fatalf("%d perte(s) comptée(s) après un lot refusé de 2", n)
	}

	e.signalerPertes()
	trouve := false
	for _, l := range logs.EntreesEnMemoire() {
		if l.Code == logs.CodeLogCentral &&
			strings.Contains(l.Message, "2 ligne(s)") &&
			strings.Contains(l.Message, "base arrêtée") {
			trouve = true
		}
	}
	if !trouve {
		t.Fatal("aucun avertissement ne dit combien de lignes manquent ni pourquoi")
	}
	if n := e.perdues.Load(); n != 0 {
		t.Errorf("compteur non remis à zéro après signalement (%d) : la même perte "+
			"serait annoncée deux fois", n)
	}
}

func TestLesSignalementsSontEspaces(t *testing.T) {
	logs.ClearLogs()
	e := NouvelEcrivain(func([]logs.LogEntry) error { return nil })
	horloge := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	e.maintenant = func() time.Time { return horloge }

	compter := func() int {
		n := 0
		for _, l := range logs.EntreesEnMemoire() {
			if l.Code == logs.CodeLogCentral {
				n++
			}
		}
		return n
	}

	e.perdues.Add(1)
	e.signalerPertes()
	horloge = horloge.Add(IntervalleVidage)
	e.perdues.Add(1)
	e.signalerPertes()
	if got := compter(); got != 1 {
		t.Fatalf("%d avertissements en une seconde : base arrêtée, le journal ne "+
			"parlerait plus que de lui-même", got)
	}

	horloge = horloge.Add(IntervalleSignalement)
	e.signalerPertes()
	if got := compter(); got != 2 {
		t.Fatalf("%d avertissement(s) après l'intervalle, attendu 2 : la perte "+
			"retenue n'est jamais annoncée", got)
	}
}

func TestLInsertionAutantDeMarqueursQueDeValeurs(t *testing.T) {
	if n := len(strings.Split(colonnes, ",")); n != nbColonnes {
		t.Fatalf("colonnes en nomme %d, nbColonnes dit %d", n, nbColonnes)
	}
	if n := len(valeursDe(entree("INFO", "x"))); n != nbColonnes {
		t.Fatalf("valeursDe rend %d valeurs pour %d colonnes : chaque INSERT échouerait", n, nbColonnes)
	}
	q := requeteInsertion(3)
	if got := strings.Count(q, "?"); got != 3*nbColonnes {
		t.Fatalf("%d marqueurs pour 3 lignes de %d colonnes :\n%s", got, nbColonnes, q)
	}
}

func TestLHeureEstStockeeEnUTC(t *testing.T) {
	paris := time.FixedZone("Paris", 2*3600)
	e := entree("INFO", "x")
	e.Timestamp = time.Date(2026, 9, 24, 14, 0, 0, 0, paris)

	got := valeursDe(e)[0].(time.Time)
	if got.Location() != time.UTC || got.Hour() != 12 {
		t.Fatalf("heure stockée = %s : deux cores sur deux fuseaux rangeraient "+
			"leurs lignes à des heures incomparables", got)
	}
}

func TestUnMessageLongEstTronqueSansCasserUnCaractere(t *testing.T) {
	long := strings.Repeat("é", tailleMessage) // 2 octets chacun
	got := tronquerOctets(long, tailleMessage)

	if len(got) > tailleMessage {
		t.Fatalf("%d octets, au-delà de la colonne (%d) : l'INSERT du lot entier échouerait",
			len(got), tailleMessage)
	}
	if !utf8.ValidString(got) {
		t.Fatal("séquence UTF-8 coupée : la colonne utf8mb4 refuserait la ligne, et le lot avec")
	}
	if !strings.HasSuffix(got, marqueTroncature) {
		t.Error("troncature sans marque : un message coupé se lirait comme complet")
	}
	if tronquerOctets("court", tailleMessage) != "court" {
		t.Error("un message court a été modifié")
	}
	if got := tronquerCaracteres("ééé", 2); got != "éé" {
		t.Errorf("tronquerCaracteres = %q, attendu « éé »", got)
	}
}
