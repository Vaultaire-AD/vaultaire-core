package reglages

import (
	"strings"
	"testing"
	"time"
)

// Le registre des durées d'exploitation.
//
// # Ce que ces tests gardent
//
// Trois propriétés dont l'échec est SILENCIEUX : une valeur hors bornes acceptée
// met une boucle en sommeil pour des années sans le dire ; un cache qui ne
// s'invalide pas fait qu'un réglage s'affiche sans agir ; une clé inconnue rend
// une période nulle, donc une boucle qui tourne sans repos et consomme un cœur.
//
// Aucun ne se voit à la lecture, et tous se voient en production.

func baseSimulee(t *testing.T) map[string]int {
	t.Helper()

	valeurs := map[string]int{}
	lireEnBase = func(cle string, min, max, def int) int {
		v, ok := valeurs[cle]
		if !ok || v < min || v > max {
			return def
		}
		return v
	}
	ecrireEnBase = func(cle string, valeur, min, max int, _ string) error {
		valeurs[cle] = valeur
		return nil
	}
	OublierTout()

	t.Cleanup(func() {
		lireEnBase = vraiLireEnBase
		ecrireEnBase = vraiEcrireEnBase
		OublierTout()
	})
	return valeurs
}

var (
	vraiLireEnBase   = lireEnBase
	vraiEcrireEnBase = ecrireEnBase
)

func horlogeFigee(t *testing.T) func(time.Duration) {
	t.Helper()
	base := time.Now()
	decalage := time.Duration(0)
	maintenant = func() time.Time { return base.Add(decalage) }
	t.Cleanup(func() { maintenant = time.Now })
	return func(d time.Duration) { decalage += d }
}

// TestChaqueReglageEstCoherent parcourt le catalogue.
//
// Un défaut hors de ses propres bornes rendrait le réglage impossible à
// satisfaire : la lecture retomberait sur un défaut que l'écriture refuserait.
// C'est le genre d'incohérence qu'on introduit en resserrant des bornes sans
// regarder le défaut.
func TestChaqueReglageEstCoherent(t *testing.T) {
	vus := map[string]bool{}

	for _, d := range Catalogue() {
		t.Run(d.Cle, func(t *testing.T) {
			if vus[d.Cle] {
				t.Fatalf("clé %q déclarée deux fois", d.Cle)
			}
			vus[d.Cle] = true

			if d.Min <= 0 {
				t.Errorf("Min = %d : une période nulle ou négative ferait tourner "+
					"la boucle sans repos", d.Min)
			}
			if d.Max < d.Min {
				t.Errorf("Max %d < Min %d", d.Max, d.Min)
			}
			if d.Defaut < d.Min || d.Defaut > d.Max {
				t.Errorf("défaut %d hors des bornes [%d..%d] : la lecture retomberait "+
					"sur une valeur que l'écriture refuse", d.Defaut, d.Min, d.Max)
			}
			if d.Unite.Duree(d.Defaut) <= 0 {
				t.Errorf("unité %q inconnue : la durée calculée serait nulle", d.Unite)
			}
			if strings.TrimSpace(d.Libelle) == "" {
				t.Error("libellé vide : la page d'administration n'aurait rien à afficher")
			}
			if strings.TrimSpace(d.Consequence) == "" {
				t.Error("conséquence vide : qui règle une cadence sans savoir ce " +
					"qu'elle coûte choisit au hasard")
			}
		})
	}

	if len(vus) == 0 {
		t.Fatal("catalogue vide : le test ne vérifierait rien")
	}
}

// TestLaBaseLEmporteSurLeDefaut : c'est toute la raison d'être du paquet.
func TestLaBaseLEmporteSurLeDefaut(t *testing.T) {
	valeurs := baseSimulee(t)
	horlogeFigee(t)

	if v := Valeur(CleVerificationEnLigne); v != 2 {
		t.Fatalf("valeur = %d sans écriture, attendu le défaut 2", v)
	}

	valeurs[CleVerificationEnLigne] = 7
	OublierTout()

	if v := Valeur(CleVerificationEnLigne); v != 7 {
		t.Errorf("valeur = %d après écriture en base, attendu 7", v)
	}
}

// TestLeDefautTientQuandLaBaseNeRepondPas.
//
// Une base neuve, vide ou injoignable doit donner un serveur qui tourne. C'est
// pourquoi le défaut est en Go et non en base : un défaut en base serait une
// ligne à insérer à la création, donc une migration, et une installation qui
// l'aurait manquée démarrerait avec des périodes nulles.
func TestLeDefautTientQuandLaBaseNeRepondPas(t *testing.T) {
	baseSimulee(t)
	horlogeFigee(t)

	lireEnBase = func(_ string, _, _, def int) int { return def }
	OublierTout()

	for _, d := range Catalogue() {
		if v := Valeur(d.Cle); v != d.Defaut {
			t.Errorf("%s = %d sans base, attendu le défaut %d", d.Cle, v, d.Defaut)
		}
	}
}

// TestLeCacheEvitLaBaseMaisPasTropLongtemps.
//
// Les boucles relisent leur période à chaque tour. Sans cache, celle du
// battement du cluster interrogerait la base toutes les trente secondes pour un
// réglage qui change une fois par an.
//
// Mais un cache long transformerait « ça ne marche pas » en « attendez » : un
// exploitant qui modifie un réglage veut le voir agir, pas se demander s'il a
// mal saisi.
func TestLeCacheEviteLaBaseMaisPasTropLongtemps(t *testing.T) {
	baseSimulee(t)
	horloge := horlogeFigee(t)

	appels := 0
	lireEnBase = func(_ string, _, _, def int) int {
		appels++
		return def
	}
	OublierTout()

	for i := 0; i < 10; i++ {
		Valeur(CleBattementCluster)
	}
	if appels != 1 {
		t.Errorf("%d lectures en base pour 10 consultations rapprochées, attendu 1", appels)
	}

	horloge(dureeDuCache + time.Second)
	Valeur(CleBattementCluster)
	if appels != 2 {
		t.Errorf("%d lectures après expiration du cache, attendu 2 — la valeur "+
			"resterait figée après un changement", appels)
	}
}

// TestEcrireInvalideLeCacheImmediatement.
//
// Sans cela, régler une durée puis relire rendrait l'ANCIENNE valeur pendant
// trente secondes. L'exploitant conclurait que son réglage n'a pas été pris.
func TestEcrireInvalideLeCacheImmediatement(t *testing.T) {
	baseSimulee(t)
	horlogeFigee(t)

	Valeur(CleSessionWeb) // remplit le cache
	if err := Ecrire(CleSessionWeb, 45, "alice"); err != nil {
		t.Fatalf("écriture : %v", err)
	}
	if v := Valeur(CleSessionWeb); v != 45 {
		t.Errorf("valeur = %d juste après écriture, attendu 45", v)
	}
}

// TestLesBornesSontAppliqueesALEcriture.
//
// Les bornes ne sont pas des limites de sécurité mais des garde-fous de saisie :
// une valeur absurde — un horodatage collé dans le champ — mettrait une boucle
// en sommeil pour des années sans le dire.
func TestLesBornesSontAppliqueesALEcriture(t *testing.T) {
	baseSimulee(t)
	horlogeFigee(t)

	d, _ := DefinitionDe(CleVerificationEnLigne)

	for _, v := range []int{d.Min - 1, d.Max + 1, 0, -5, 1700000000} {
		if err := Ecrire(CleVerificationEnLigne, v, "alice"); err == nil {
			t.Errorf("valeur %d acceptée hors des bornes [%d..%d]", v, d.Min, d.Max)
		}
	}
	for _, v := range []int{d.Min, d.Defaut, d.Max} {
		if err := Ecrire(CleVerificationEnLigne, v, "alice"); err != nil {
			t.Errorf("valeur %d refusée alors qu'elle est dans les bornes : %v", v, err)
		}
	}
}

// TestUneValeurHorsBornesEnBaseRetombeSurLeDefaut.
//
// Les bornes peuvent être resserrées après coup, ou la ligne écrite à la main.
// Une valeur devenue hors bornes ne doit pas être appliquée : le défaut est le
// choix prudent, et il est journalisé par la couche base.
func TestUneValeurHorsBornesEnBaseRetombeSurLeDefaut(t *testing.T) {
	valeurs := baseSimulee(t)
	horlogeFigee(t)

	valeurs[CleBalayageServices] = 999999
	OublierTout()

	d, _ := DefinitionDe(CleBalayageServices)
	if v := Valeur(CleBalayageServices); v != d.Defaut {
		t.Errorf("valeur = %d pour une entrée hors bornes, attendu le défaut %d", v, d.Defaut)
	}
}

// TestCleInconnueRendZero.
//
// Zéro plutôt qu'un défaut inventé : la boucle qui l'emploierait s'arrête et le
// dit, au lieu de tourner à une cadence choisie au hasard. Voir Boucle.
func TestCleInconnueRendZero(t *testing.T) {
	baseSimulee(t)
	horlogeFigee(t)

	if v := Valeur("cle_qui_nexiste_pas"); v != 0 {
		t.Errorf("valeur = %d pour une clé inconnue, attendu 0", v)
	}
	if d := Duree("cle_qui_nexiste_pas"); d != 0 {
		t.Errorf("durée = %s pour une clé inconnue, attendue nulle", d)
	}
	if err := Ecrire("cle_qui_nexiste_pas", 5, "alice"); err == nil {
		t.Error("écriture acceptée sur une clé inconnue")
	}
}

// TestReinitialiserEcritLeDefautPlutotQueSupprimer.
//
// Une ligne supprimée et un défaut écrit se lisent pareil aujourd'hui, mais la
// ligne porte `updated_by` — et savoir QUI a remis un réglage au défaut est
// exactement ce qu'on cherchera si une cadence change sans explication.
func TestReinitialiserEcritLeDefautPlutotQueSupprimer(t *testing.T) {
	valeurs := baseSimulee(t)
	horlogeFigee(t)

	d, _ := DefinitionDe(CleSessionsDucky)

	if err := Ecrire(CleSessionsDucky, d.Max, "alice"); err != nil {
		t.Fatalf("%v", err)
	}
	if err := Reinitialiser(CleSessionsDucky, "bob"); err != nil {
		t.Fatalf("%v", err)
	}

	if _, present := valeurs[CleSessionsDucky]; !present {
		t.Error("la ligne a été supprimée : on perd qui a remis le défaut")
	}
	if valeurs[CleSessionsDucky] != d.Defaut {
		t.Errorf("valeur en base = %d, attendu le défaut %d", valeurs[CleSessionsDucky], d.Defaut)
	}
}

// TestLesUnitesConvertissent.
func TestLesUnitesConvertissent(t *testing.T) {
	cas := []struct {
		u        Unite
		v        int
		attendue time.Duration
	}{
		{Secondes, 30, 30 * time.Second},
		{Minutes, 2, 2 * time.Minute},
		{Heures, 24, 24 * time.Hour},
		{Unite("inconnue"), 5, 0},
	}
	for _, c := range cas {
		if got := c.u.Duree(c.v); got != c.attendue {
			t.Errorf("%q.Duree(%d) = %s, attendu %s", c.u, c.v, got, c.attendue)
		}
	}
}

// TestEtatCourantMarqueCeQuiAEteTouche.
//
// C'est la question qu'on se pose devant un serveur qu'on ne connaît pas :
// qu'est-ce qui a été modifié ici ?
func TestEtatCourantMarqueCeQuiAEteTouche(t *testing.T) {
	baseSimulee(t)
	horlogeFigee(t)

	d, _ := DefinitionDe(CleNettoyageCluster)
	if err := Ecrire(CleNettoyageCluster, d.Defaut+10, "alice"); err != nil {
		t.Fatalf("%v", err)
	}

	for _, e := range EtatCourant() {
		if e.Cle == CleNettoyageCluster {
			if e.AuDefaut {
				t.Error("réglage modifié présenté comme étant au défaut")
			}
			continue
		}
		if !e.AuDefaut {
			t.Errorf("%s présenté comme modifié alors qu'il ne l'est pas", e.Cle)
		}
	}
}
