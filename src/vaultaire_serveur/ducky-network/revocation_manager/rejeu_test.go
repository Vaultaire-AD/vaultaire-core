package revocationmanager

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/revocation"
)

// Le rejeu du core — TO-DO 49.
//
// Ce qui est éprouvé ici est la DÉCISION : à qui remettre, quoi, et quand. La
// base et le réseau sont remplacés par des fonctions ; les requêtes, elles, ont
// leur test contre une vraie base (db_revocation/rejeu_base_test.go).

func ordre(id int, mode revocation.Mode) revocation.Order {
	return revocation.Order{ID: id, Mode: mode, Username: "bob.durand", Reason: revocation.ReasonCompromised}
}

func attente(id int, mode revocation.Mode, essais int, depuis int64) dbrevocation.EnAttente {
	e := dbrevocation.EnAttente{Ordre: ordre(id, mode), Statut: revocation.StatusPending, Essais: essais}
	if depuis >= 0 {
		e.DepuisLeDernier = sql.NullInt64{Int64: depuis, Valid: true}
	}
	return e
}

func TestLEspacementDoubleEtPlafonne(t *testing.T) {
	cas := []struct {
		essais int
		veut   time.Duration
	}{
		{0, 0},
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{3, 40 * time.Second},
		{4, 80 * time.Second},
		{5, 160 * time.Second},
		{6, 5 * time.Minute},
		{7, 5 * time.Minute},
		{500, 5 * time.Minute}, // pas de débordement : le plafond coupe la boucle
	}
	for _, c := range cas {
		if a := attenteApres(c.essais); a != c.veut {
			t.Errorf("après %d essai(s) : %s, attendu %s", c.essais, a, c.veut)
		}
	}
	if PlafondDuRejeu >= 10*time.Minute {
		t.Errorf("le plafond (%s) atteint le rappel de l'agent : le core ne serait plus le plus rapide des deux",
			PlafondDuRejeu)
	}
	if PremierRejeu <= 5*time.Second {
		t.Errorf("le premier rejeu (%s) tombe pendant que l'agent attend encore la mort des processus (5 s) : "+
			"il rejouerait un ordre en cours d'application", PremierRejeu)
	}
}

func TestUnOrdreJamaisRemisEstDuToutDeSuite(t *testing.T) {
	if !estDu(attente(1, revocation.ModeSoft, 0, -1)) {
		t.Fatal("un ordre jamais remis attend : la machine absente au déclenchement ne le recevrait pas à son retour")
	}
	// Un compte d'essais sans date ne doit pas bloquer non plus.
	if !estDu(attente(1, revocation.ModeSoft, 3, -1)) {
		t.Fatal("un ordre sans date de dernier essai n'est jamais dû : il resterait en attente pour toujours")
	}
}

func TestUnOrdreRemisAttendSonTour(t *testing.T) {
	if estDu(attente(1, revocation.ModeSoft, 1, 9)) {
		t.Error("rejoué 9 s après le premier envoi : avant les 10 s")
	}
	if !estDu(attente(1, revocation.ModeSoft, 1, 10)) {
		t.Error("pas rejoué à 10 s")
	}
	if estDu(attente(1, revocation.ModeSoft, 3, 39)) {
		t.Error("rejoué 39 s après le troisième essai : avant les 40 s")
	}
	if !estDu(attente(1, revocation.ModeSoft, 40, 300)) {
		t.Error("un ordre au plafond n'est plus rejoué : il n'y a pas d'abandon")
	}
}

// banc assemble un tour avec des doublures et relève ce qui s'y passe.
type banc struct {
	src        sourceDuRejeu
	requetes   int
	lues       []string
	remis      map[string][]int
	notes      map[string][]int
	echecEnvoi bool
}

func nouveauBanc(connectees []string, enBase map[string][]dbrevocation.EnAttente) *banc {
	b := &banc{remis: map[string][]int{}, notes: map[string][]int{}}
	b.src = sourceDuRejeu{
		connectees: func() []string { return connectees },
		machinesEnAttente: func() ([]string, error) {
			b.requetes++
			var m []string
			for id := range enBase {
				m = append(m, id)
			}
			return m, nil
		},
		enAttentePour: func(id string) ([]dbrevocation.EnAttente, error) {
			b.lues = append(b.lues, id)
			return enBase[id], nil
		},
		remettre: func(id string, ordres []revocation.Order) bool {
			if b.echecEnvoi {
				return false
			}
			for _, o := range ordres {
				b.remis[id] = append(b.remis[id], o.ID)
			}
			return true
		},
		noter: func(id string, ids []int) { b.notes[id] = append(b.notes[id], ids...) },
	}
	return b
}

func TestSansMachineConnecteeLaBaseNEstPasInterrogee(t *testing.T) {
	b := nouveauBanc(nil, map[string][]dbrevocation.EnAttente{"pc-01": {attente(1, revocation.ModeSoft, 0, -1)}})
	if n := unTourDeRejeu(b.src); n != 0 || b.requetes != 0 {
		t.Fatalf("%d machine(s) servie(s), %d requête(s) : un core sans machine interroge la base toutes les 5 s", n, b.requetes)
	}
}

func TestUneMachineAbsenteNEstNiLueNiServie(t *testing.T) {
	b := nouveauBanc([]string{"pc-02"}, map[string][]dbrevocation.EnAttente{"pc-01": {attente(1, revocation.ModeSoft, 0, -1)}})
	if n := unTourDeRejeu(b.src); n != 0 || len(b.lues) != 0 || len(b.remis) != 0 {
		t.Fatalf("servies=%d lues=%v remis=%v : une machine tenue par un autre core ne se sert pas d'ici", n, b.lues, b.remis)
	}
}

func TestLaListeEntierePartDansLOrdre(t *testing.T) {
	// Le verrouillage 7 a déjà été essayé il y a 3 s : pas dû. La levée 9 n'a
	// jamais été remise : due. Remettre la 9 SEULE, puis la 7 plus tard,
	// laisserait la machine verrouillée alors que le compte est rétabli.
	b := nouveauBanc([]string{"PC-01"}, map[string][]dbrevocation.EnAttente{
		"pc-01": {attente(7, revocation.ModeSoft, 1, 3), attente(9, revocation.ModeUnlock, 0, -1)},
	})
	if n := unTourDeRejeu(b.src); n != 1 {
		t.Fatalf("%d machine servie, attendu 1", n)
	}
	// Remis à l'identifiant ANNONCÉ par la machine, noté sous celui de la base.
	if got := b.remis["PC-01"]; len(got) != 2 || got[0] != 7 || got[1] != 9 {
		t.Fatalf("remis %v, attendu [7 9] : l'ordre chronologique est ce qui garde un compte rétabli ouvert", b.remis)
	}
	if got := b.notes["pc-01"]; len(got) != 2 {
		t.Fatalf("essais notés %v : sans cela le tour suivant rejoue la même liste, toutes les 5 s", b.notes)
	}
}

func TestRienNEstRemisTantQueRienNEstDu(t *testing.T) {
	b := nouveauBanc([]string{"pc-01"}, map[string][]dbrevocation.EnAttente{
		"pc-01": {attente(7, revocation.ModeSoft, 1, 3), attente(8, revocation.ModeSoft, 2, 12)},
	})
	if n := unTourDeRejeu(b.src); n != 0 || len(b.remis) != 0 || len(b.notes) != 0 {
		t.Fatalf("servies=%d remis=%v notes=%v : rejoué avant l'heure", n, b.remis, b.notes)
	}
}

func TestUnEnvoiEchoueNEstPasCompte(t *testing.T) {
	b := nouveauBanc([]string{"pc-01"}, map[string][]dbrevocation.EnAttente{"pc-01": {attente(7, revocation.ModeSoft, 0, -1)}})
	b.echecEnvoi = true
	if n := unTourDeRejeu(b.src); n != 0 || len(b.notes) != 0 {
		t.Fatalf("servies=%d notes=%v : un envoi qui n'est pas parti a été compté pour un essai — "+
			"le suivant attendrait dix secondes pour rien", n, b.notes)
	}
}

func TestUneBaseEnPanneNeFaitRienPartir(t *testing.T) {
	b := nouveauBanc([]string{"pc-01"}, nil)
	b.src.machinesEnAttente = func() ([]string, error) { return nil, errors.New("base indisponible") }
	if n := unTourDeRejeu(b.src); n != 0 {
		t.Fatalf("%d machine servie sur une lecture en échec", n)
	}
}

func TestLaTrameDeListeGardeSaForme(t *testing.T) {
	trame := buildListFrame("cle", []revocation.Order{ordre(7, revocation.ModeSoft), ordre(9, revocation.ModeUnlock)})
	veut := strings.Join([]string{
		"06_05", "serveur_central", "cle", "2",
		"7|soft|bob.durand|compromised",
		"9|unlock|bob.durand|compromised",
	}, "\n")
	if trame != veut {
		t.Fatalf("trame :\n%s\nattendu :\n%s\n— c'est celle que les agents déjà déployés savent lire", trame, veut)
	}
}
