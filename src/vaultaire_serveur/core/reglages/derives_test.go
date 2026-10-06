package reglages

import (
	"testing"
	"time"
)

// Aucune cadence admise ne doit couper une session saine (TO-DO 110).
//
// Le test parcourt TOUTES les valeurs que le réglage accepte, pas seulement
// son maximum : le défaut d'origine apparaissait à six minutes, puis de
// nouveau à onze, et un test au seul maximum aurait pu passer avec une formule
// fausse entre les deux.

func bornesDeLaCadence(t *testing.T) (int, int) {
	t.Helper()
	d, ok := index[CleVerificationEnLigne]
	if !ok {
		t.Fatal("réglage check_online_minutes absent du catalogue")
	}
	return d.Min, d.Max
}

// Le balayage passe à chaque cadence, juste après avoir envoyé le battement.
// Une session saine y arrive avec une cadence de silence, plus le temps de
// réponse. Elle doit survivre — et survivre aussi à UN battement perdu.
func TestAucuneCadenceNeCoupeUneSessionSaine(t *testing.T) {
	min, max := bornesDeLaCadence(t)
	const tempsDeReponse = 30 * time.Second

	for m := min; m <= max; m++ {
		cadence := time.Duration(m) * time.Minute
		tolerance := ToleranceDeSilencePour(cadence)

		if silence := cadence + tempsDeReponse; silence >= tolerance {
			t.Errorf("cadence %d min : une session saine a %s de silence au balayage, la tolérance est %s — "+
				"tout le parc serait coupé à chaque tour", m, silence, tolerance)
		}
		if silence := 2*cadence + tempsDeReponse; silence >= tolerance {
			t.Errorf("cadence %d min : un seul battement perdu (%s de silence) dépasse la tolérance %s",
				m, silence, tolerance)
		}
		// Deux battements perdus de suite : là, le pair est parti.
		if silence := 3 * cadence; m > 1 && silence < tolerance {
			t.Errorf("cadence %d min : deux battements perdus (%s) ne dépassent pas la tolérance %s — "+
				"une machine éteinte ne serait jamais retirée", m, silence, tolerance)
		}
	}
}

// La ligne en base ne doit jamais expirer avant la session qu'elle décrit.
func TestLaLigneEnBaseSurvitALaSession(t *testing.T) {
	min, max := bornesDeLaCadence(t)
	for m := min; m <= max; m++ {
		cadence := time.Duration(m) * time.Minute
		validite, tolerance := ValiditeDeSessionPour(cadence), ToleranceDeSilencePour(cadence)

		// La ligne est rafraîchie à chaque battement répondu. Tant que le
		// balayage tolère la session, la ligne doit exister.
		if validite < tolerance+cadence {
			t.Errorf("cadence %d min : validité en base %s, tolérance en mémoire %s — "+
				"la ligne expirerait avant que le balayage ne ferme la session", m, validite, tolerance)
		}
		if validite <= 2*cadence {
			t.Errorf("cadence %d min : validité %s, soit moins de deux battements — "+
				"« status -c » perdrait le parc entre deux battements", m, validite)
		}
	}
}

// À la cadence par défaut, rien ne change : cinq et dix minutes, comme avant.
func TestLesValeursParDefautNeBougentPas(t *testing.T) {
	d := index[CleVerificationEnLigne]
	cadence := d.Unite.Duree(d.Defaut)
	if got := ToleranceDeSilencePour(cadence); got != 5*time.Minute {
		t.Errorf("tolérance à la cadence par défaut : %s, attendu 5 min", got)
	}
	if got := ValiditeDeSessionPour(cadence); got != 10*time.Minute {
		t.Errorf("validité à la cadence par défaut : %s, attendu 10 min", got)
	}
}

// Les deux cas du constat, nommément.
func TestLesDeuxCasDuConstat(t *testing.T) {
	if got := ToleranceDeSilencePour(6 * time.Minute); got <= 6*time.Minute {
		t.Errorf("cadence 6 min : tolérance %s — c'est le premier défaut du point 110", got)
	}
	if got := ValiditeDeSessionPour(11 * time.Minute); got <= 11*time.Minute {
		t.Errorf("cadence 11 min : validité %s — c'est le second défaut du point 110", got)
	}
}

// Les fonctions qui lisent le réglage le suivent sans redémarrage.
func TestLesDureesSuiventLeReglage(t *testing.T) {
	baseSimulee(t)

	if err := Ecrire(CleVerificationEnLigne, 20, "test"); err != nil {
		t.Fatal(err)
	}
	if got := ToleranceDeSilence(); got != 41*time.Minute {
		t.Errorf("tolérance pour 20 min : %s, attendu 41 min", got)
	}
	if got := ValiditeDeSession(); got != 61*time.Minute {
		t.Errorf("validité pour 20 min : %s, attendu 61 min", got)
	}
	if got := LigneCadenceEnLigne(); got != "online:20" {
		t.Errorf("ligne annoncée à l'agent : %q, attendu « online:20 »", got)
	}

	if err := Ecrire(CleVerificationEnLigne, 2, "test"); err != nil {
		t.Fatal(err)
	}
	if got := ToleranceDeSilence(); got != 5*time.Minute {
		t.Errorf("retour à 2 min : tolérance %s, attendu 5 min", got)
	}
}
