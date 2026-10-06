package revocation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TO-DO 134 — la demande 06_04 part à chaque tunnel rétabli, pas seulement au
// démarrage de l'agent.

// Le scénario 3 de la recette : couper le réseau une minute, le rétablir. Le
// tunnel revient avec une clé de session neuve — c'est elle qui déclenche.
func TestUnTunnelRetabliReclameLesOrdres(t *testing.T) {
	var suivi suiviDesDemandes
	t0 := time.Now()

	if due, motif := suivi.doitDemander("cle-1", t0); !due || motif != "demarrage" {
		t.Fatalf("au demarrage : %v (%s), attendu une demande", due, motif)
	}
	suivi.noter("cle-1", t0)

	if due, _ := suivi.doitDemander("cle-1", t0.Add(30*time.Second)); due {
		t.Error("une seconde demande est partie alors que la session n'a pas change")
	}

	// Le tunnel tombe : plus de clé. Rien à demander, et rien d'oublié.
	if due, _ := suivi.doitDemander("", t0.Add(40*time.Second)); due {
		t.Error("une demande est partie sans session")
	}

	// Il revient, une minute plus tard.
	due, motif := suivi.doitDemander("cle-2", t0.Add(100*time.Second))
	if !due || motif != "tunnel retabli" {
		t.Fatalf("apres retablissement : %v (%s) — l'ordre emis pendant la coupure "+
			"attendrait le redemarrage de l'agent", due, motif)
	}
}

// Le rappel : la session tient, mais un ordre poussé en vain — ou appliqué en
// échec — attend. Sans rappel il attendrait la prochaine coupure du tunnel.
func TestLeRappelPartTantQueLaSessionTient(t *testing.T) {
	var suivi suiviDesDemandes
	t0 := time.Now()
	suivi.noter("cle-1", t0)

	if due, _ := suivi.doitDemander("cle-1", t0.Add(RappelDesOrdres-time.Second)); due {
		t.Error("rappel parti avant l'echeance")
	}
	if due, motif := suivi.doitDemander("cle-1", t0.Add(RappelDesOrdres)); !due || motif != "rappel" {
		t.Errorf("a l'echeance : %v (%s), attendu un rappel", due, motif)
	}
}

// Une demande par événement : la clé notée, la scrutation — toutes les deux
// secondes — ne doit pas en renvoyer une à chaque tour.
func TestUneSeuleDemandeParSession(t *testing.T) {
	var suivi suiviDesDemandes
	t0 := time.Now()
	demandes := 0
	for i := 0; i < 100; i++ {
		maintenant := t0.Add(time.Duration(i) * pasDeSurveillance)
		if due, _ := suivi.doitDemander("cle-1", maintenant); due {
			demandes++
			suivi.noter("cle-1", maintenant)
		}
	}
	if demandes != 1 {
		t.Errorf("%d demandes en %s sur une session stable, attendu 1", demandes, 100*pasDeSurveillance)
	}
}

// Le rappel est une borne de sûreté : dix minutes au plus pendant lesquelles un
// compte coupé peut rester ouvert sur une machine pourtant connectée.
func TestLeRappelResteCourt(t *testing.T) {
	if RappelDesOrdres > 15*time.Minute {
		t.Errorf("RappelDesOrdres = %s : c'est la duree pendant laquelle un ordre pousse en vain "+
			"reste sans effet sur une machine connectee", RappelDesOrdres)
	}
}

// SENTINELLE — le défaut du point était un écart entre ce que le code disait et
// ce qu'il faisait : `AskPending` n'avait qu'UN appelant, lancé une fois.
//
// Ce test interdit d'y revenir : la demande ne doit être émise que par la
// surveillance, et la surveillance doit être lancée par l'amorçage de l'agent.
func TestLaDemandeNEstEmiseQueParLaSurveillance(t *testing.T) {
	var appelants []string
	racine := ".."
	err := filepath.Walk(racine, func(chemin string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(chemin, ".go") || strings.HasSuffix(chemin, "_test.go") {
			return nil
		}
		contenu, err := os.ReadFile(chemin)
		if err != nil {
			return nil
		}
		for _, ligne := range strings.Split(string(contenu), "\n") {
			nette := strings.TrimSpace(ligne)
			if strings.HasPrefix(nette, "//") || strings.HasPrefix(nette, "func AskPending") {
				continue
			}
			if strings.Contains(nette, "AskPending(") {
				appelants = append(appelants, filepath.ToSlash(chemin))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(appelants) != 1 || !strings.HasSuffix(appelants[0], "revocation/rattrapage.go") {
		t.Errorf("AskPending est appelee depuis %v, attendu le seul rattrapage.go : une demande "+
			"emise ailleurs, une fois, est exactement le defaut du point 134", appelants)
	}

	amorce, err := os.ReadFile(filepath.Join(racine, "gpo", "bootstrap.go"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(string(amorce), "go revocation.SurveillerLesOrdres(") &&
		!strings.Contains(string(amorce), "revocation.SurveillerLesOrdres(CurrentSessionKey)") {
		t.Error("l'amorcage de l'agent ne lance plus la surveillance des ordres : plus rien ne les reclame")
	}
}
