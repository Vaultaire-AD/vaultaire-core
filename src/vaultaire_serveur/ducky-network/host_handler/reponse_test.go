package hosthandler

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Le garde-fou de la composition des réponses.
//
// # Le défaut qu'il empêche de revenir
//
// Les trames 04_02, 04_04, 04_06 et 04_08 étaient composées à la main, par
// concaténation, avec l'en-tête des REQUÊTES — cinq lignes au lieu de trois :
//
//	"04_04\nserver_central\n" + sk + "\n" + un + "\n" + cid + "\n" + …
//
// L'agent, qui lit à partir de la quatrième ligne, prenait « vaultaire » pour la
// première ligne de contenu.
//
// Trois des quatre trames sont des accusés dont le contenu n'est jamais
// analysé — « ok », « ack ». Le décalage y était parfaitement invisible. Seule
// 04_04 porte un contenu que quelqu'un lit, et c'est la seule qui a parlé : les
// trois autres seraient restées fausses indéfiniment.
//
// D'où un test qui porte sur la FORME du code et non sur son résultat. Le
// résultat des trois accusés ne dit rien ; c'est la façon de les composer qui
// est en cause.

// TestAucuneTrameCompoJeeALaMain.
//
// Toute réponse 04_xx passe par trame.ReponseClient. Une concaténation
// manuscrite est refusée même si elle est juste : elle le serait par chance, et
// la suivante ne le serait pas.
func TestAucuneTrameComposeeALaMain(t *testing.T) {
	fichiers, err := filepath.Glob("*.go")
	if err != nil || len(fichiers) == 0 {
		t.Fatalf("aucune source trouvee : %v", err)
	}

	// Un littéral de trame en début de chaîne : "04_02\n…", "04_11\n…".
	litteral := regexp.MustCompile(`"0\d_\d\d\\n`)

	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		contenu, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("lecture de %s : %v", f, err)
		}
		for i, ligne := range strings.Split(string(contenu), "\n") {
			if litteral.MatchString(ligne) {
				t.Errorf("%s:%d compose une trame a la main :\n\t%s\n"+
					"  Utilisez trame.ReponseClient — l'en-tete d'une reponse fait TROIS "+
					"lignes, celui d'une requete cinq, et rien d'autre ne le garantit.",
					f, i+1, strings.TrimSpace(ligne))
			}
		}
	}
}

// TestToutesLesReponsesPassentParLeConstructeur.
//
// L'inverse du précédent : le constructeur est bien employé, et pas seulement
// « pas contourné ». Un fichier qui ne répondrait plus rien passerait le premier
// test sans rien garantir.
func TestToutesLesReponsesPassentParLeConstructeur(t *testing.T) {
	fichiers, _ := filepath.Glob("*.go")
	var tout strings.Builder
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		contenu, _ := os.ReadFile(f)
		tout.Write(contenu)
	}
	sources := tout.String()

	appels := strings.Count(sources, "trame.ReponseClient(")
	// Sept réponses : 04_02, 04_04, 04_06, 04_08, 04_10, 04_11, 04_13.
	// 04_14 n'en a pas — une sortie propre n'attend pas d'accusé.
	if appels < 7 {
		t.Errorf("%d appel(s) a trame.ReponseClient, au moins 7 attendus : "+
			"une reponse a probablement ete retiree ou reecrite a la main", appels)
	}
}
