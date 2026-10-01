package decouverte

import (
	"strings"
	"testing"
	"time"
)

// La cadence arrive du RÉSEAU et pilote une boucle infinie : ces tests gardent
// les deux propriétés qui empêchent une valeur fautive de transformer l'agent
// en générateur de trafic, ou de le rendre sourd à un nœud retiré.

// avecCadence rétablit la valeur d'origine après le test : l'état est un
// paquet, et un test qui laisse 5 minutes derrière lui ferait échouer le
// suivant sans rapport avec ce qu'il vérifie.
func avecCadence(t *testing.T, valeur time.Duration) {
	t.Helper()
	cadenceMu.Lock()
	ancienne := cadence
	cadence = valeur
	cadenceMu.Unlock()
	t.Cleanup(func() {
		cadenceMu.Lock()
		cadence = ancienne
		cadenceMu.Unlock()
	})
}

// Le préfixe est déclaré des deux côtés du réseau et rien ne les lie à la
// compilation. Les faire diverger ferait rejeter la ligne comme un nœud
// malformé — visible seulement dans un WARNING que personne ne lit.
func TestLePrefixeResteCeluiDuCore(t *testing.T) {
	if PrefixeCadence != "disco:" {
		t.Errorf("PrefixeCadence = %q : la valeur doit rester identique à celle du "+
			"core (host_handler.PrefixeCadenceDecouverte)", PrefixeCadence)
	}
}

func TestLaCadenceEstBornee(t *testing.T) {
	cas := []struct {
		nom      string
		ligne    string
		attendu  time.Duration
		pourquoi string
	}{
		{
			nom:     "valeur ordinaire",
			ligne:   "disco:15",
			attendu: 15 * time.Minute,
		},
		{
			nom:      "zéro",
			ligne:    "disco:0",
			attendu:  CadenceMinimum,
			pourquoi: "une cadence nulle ferait tourner la boucle sans attendre",
		},
		{
			nom:      "négative",
			ligne:    "disco:-10",
			attendu:  CadenceMinimum,
			pourquoi: "une attente négative revient à ne pas attendre",
		},
		{
			nom:      "sous le plancher",
			ligne:    "disco:1",
			attendu:  CadenceMinimum,
			pourquoi: "une demande de liste par minute et par poste",
		},
		{
			nom:      "au-dessus du plafond",
			ligne:    "disco:100000",
			attendu:  CadenceMaximum,
			pourquoi: "deux mois sans relire la liste",
		},
		{
			nom:     "espaces autour de la valeur",
			ligne:   "disco: 20 ",
			attendu: 20 * time.Minute,
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			avecCadence(t, CadenceParDefaut)
			appliquerCadenceDepuis(c.ligne)
			if got := Cadence(); got != c.attendu {
				t.Errorf("%q donne %s, attendu %s (%s)", c.ligne, got, c.attendu, c.pourquoi)
			}
		})
	}
}

// Une ligne illisible ne doit RIEN changer : la cadence en vigueur a été
// décidée par un core, et la remplacer par le défaut à la première trame
// abîmée annulerait silencieusement le réglage.
func TestUneLigneIllisibleNeChangeRien(t *testing.T) {
	for _, ligne := range []string{"disco:", "disco:abc", "disco:12min", "disco:1.5"} {
		avecCadence(t, 17*time.Minute)
		appliquerCadenceDepuis(ligne)
		if got := Cadence(); got != 17*time.Minute {
			t.Errorf("%q a changé la cadence en %s", ligne, got)
		}
	}
}

// Sans ce réveil, une cadence raccourcie n'entrerait en vigueur qu'au terme de
// l'ancienne attente : jusqu'à une demi-heure de retard sur un changement fait
// précisément pour aller plus vite.
func TestUnChangementReveilleLaBoucle(t *testing.T) {
	avecCadence(t, 30*time.Minute)
	viderReveil()

	definirCadence(10 * time.Minute)
	select {
	case <-reveilCadence:
	default:
		t.Error("cadence changée sans réveil de la boucle")
	}
}

// Recevoir la même valeur à chaque trame ne doit pas réveiller la boucle : la
// 04_04 arrive à chaque tour, et un réveil par tour ferait redemander la liste
// en continu — l'inverse de ce que la cadence règle.
func TestUneValeurIdentiqueNeReveillePas(t *testing.T) {
	avecCadence(t, 30*time.Minute)
	viderReveil()

	definirCadence(30 * time.Minute)
	select {
	case <-reveilCadence:
		t.Error("une cadence inchangée a réveillé la boucle")
	default:
	}
}

func viderReveil() {
	select {
	case <-reveilCadence:
	default:
	}
}

// La ligne de cadence n'est pas un nœud : elle ne doit ni entrer dans la liste,
// ni compter comme une ligne rejetée — sinon chaque trame paraîtrait tronquée,
// puisque le nombre annoncé en première ligne ne compte que des nœuds.
func TestLaLigneDeCadenceNEstPasUnNoeud(t *testing.T) {
	avecCadence(t, CadenceParDefaut)

	contenu := strings.Join([]string{
		"2",
		"core-a|10.0.0.1|8443|core|1|SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"core-b|10.0.0.2|8443|core|2|SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		"disco:12",
	}, "\n")

	noeuds, err := AnalyserListe(contenu)
	if err != nil {
		t.Fatal(err)
	}
	if len(noeuds) != 2 {
		t.Fatalf("%d nœud(s) retenu(s), attendu 2 : %+v", len(noeuds), noeuds)
	}
	if got := Cadence(); got != 12*time.Minute {
		t.Errorf("cadence = %s, attendu 12m : la ligne n'a pas été appliquée", got)
	}
}

// Une 04_04 d'un core plus ancien ne porte aucune ligne de cadence. L'agent
// doit garder la sienne : c'est la compatibilité qui a fait choisir la queue et
// le préfixe plutôt qu'un champ de plus.
func TestUneTrameSansCadenceLaisseLaValeurEnPlace(t *testing.T) {
	avecCadence(t, 42*time.Minute)

	_, err := AnalyserListe("1\ncore-a|10.0.0.1|8443|core|1|SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if got := Cadence(); got != 42*time.Minute {
		t.Errorf("cadence = %s : une trame sans « %s » a écrasé la valeur en vigueur",
			got, PrefixeCadence)
	}
}
