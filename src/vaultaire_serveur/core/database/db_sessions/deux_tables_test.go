package dbsessions

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LE test de non-régression du point 92.
//
// Une ligne de `did_login` vaut une session DUCKY : un tunnel, une clé, une
// connexion. `status -c` la lit pour énumérer les machines. Le point 68 y a
// écrit les sessions PAM, faute de table où les mettre, et une machine sur
// laquelle quelqu'un travaillait apparaissait deux fois (recette du 24/09).
//
// Les deux tables ne doivent plus jamais se croiser. Rien dans le compilateur
// ne peut le garantir — ce sont des chaînes de caractères —, d'où ce test.
//
// # Pourquoi lire les LITTÉRAUX et non le texte du fichier
//
// Les deux fichiers se citent l'un l'autre en commentaire, et c'est voulu :
// c'est ainsi qu'on comprend pourquoi la séparation existe. Chercher le nom de
// table dans le texte brut les ferait rougir tous les deux. Le test analyse
// donc la source et n'inspecte que les chaînes — c'est-à-dire ce qui part
// réellement à la base.

// tablesCitees rend les tables nommées dans les littéraux chaîne d'un fichier.
func tablesCitees(t *testing.T, chemin string) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("%s illisible : %v", chemin, err)
	}
	fichier, err := parser.ParseFile(token.NewFileSet(), chemin, src, 0)
	if err != nil {
		t.Fatalf("%s non analysable : %v", chemin, err)
	}

	trouvees := map[string]bool{}
	ast.Inspect(fichier, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		for _, table := range []string{"did_login", "user_sessions"} {
			if strings.Contains(lit.Value, table) {
				trouvees[table] = true
			}
		}
		return true
	})
	return trouvees
}

func TestStatusCNeLitQueLesSessionsDucky(t *testing.T) {
	fichiers, err := filepath.Glob("status_get_clients_connected*.go")
	if err != nil || len(fichiers) == 0 {
		t.Fatalf("aucune lecture de `status -c` trouvée : %v", err)
	}
	for _, f := range fichiers {
		tables := tablesCitees(t, f)
		if tables["user_sessions"] {
			t.Errorf("%s interroge user_sessions : une session PAM y ferait "+
				"réapparaître une machine en double, c'est exactement le défaut "+
				"que la table séparée corrige", f)
		}
		if !tables["did_login"] {
			t.Errorf("%s n'interroge plus did_login : `status -c` ne verrait "+
				"plus aucune machine", f)
		}
	}
}

func TestLesSessionsUtilisateurNeTouchentPasADidLogin(t *testing.T) {
	tables := tablesCitees(t, "sessions_utilisateur.go")
	if tables["did_login"] {
		t.Error("sessions_utilisateur.go interroge did_login : les deux natures " +
			"de session se remélangeraient")
	}
	if !tables["user_sessions"] {
		t.Error("sessions_utilisateur.go n'interroge pas user_sessions")
	}
}

// La purge doit couvrir les DEUX tables. Une seule purgée laisserait des
// sessions éternelles dans l'autre — et c'est la table utilisateur qui serait
// oubliée, puisque c'est la nouvelle.
func TestLaPurgeCouvreLesDeuxTables(t *testing.T) {
	if !tablesCitees(t, "clean_up_expired_sessions.go")["did_login"] {
		t.Error("la purge ne touche plus did_login")
	}
	if !tablesCitees(t, "sessions_utilisateur.go")["user_sessions"] {
		t.Error("aucune purge des sessions utilisateur")
	}
	// Le chaînage lui-même : clean_up_expired_sessions doit appeler la purge
	// des sessions utilisateur, sinon les deux vivent dans des boucles
	// différentes et finissent par tourner à des cadences différentes.
	src, err := os.ReadFile("clean_up_expired_sessions.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "PurgerSessionsUtilisateurExpirees") {
		t.Error("la purge des sessions Ducky n'enchaîne pas sur celle des " +
			"sessions utilisateur")
	}
}

// L'échéance vient d'une seule source. Trois copies du même nombre vivaient
// dans trois fichiers ; y en remettre une ici ferait expirer les sessions
// utilisateur à une autre heure que les autres.
func TestLEcheanceVientDeLaConstantePartagee(t *testing.T) {
	src, err := os.ReadFile("sessions_utilisateur.go")
	if err != nil {
		t.Fatal(err)
	}
	texte := string(src)
	if !strings.Contains(texte, "EcheanceSession()") {
		t.Error("les sessions utilisateur n'emploient pas EcheanceSession()")
	}
	if strings.Contains(texte, "time.Now().Add(") {
		t.Error("une échéance est recalculée sur place au lieu d'employer " +
			"EcheanceSession()")
	}
}
