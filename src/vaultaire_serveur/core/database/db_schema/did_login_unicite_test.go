package dbschema

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// L'unicité de `did_login` tient à trois choses qui doivent rester d'accord :
// le CREATE TABLE d'une base neuve, la migration d'une base existante, et les
// deux écritures qui n'ont plus le droit de lire avant d'écrire.
//
// Aucune de ces vérifications n'a besoin de base : elles portent sur le TEXTE
// des requêtes, qui est précisément ce qui diverge quand on corrige un fichier
// et pas l'autre.

func lireSource(t *testing.T, chemin string) string {
	t.Helper()
	contenu, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("lecture de %s : %v", chemin, err)
	}
	return string(contenu)
}

// Une base NEUVE doit naître avec la contrainte. Sans cela, elle ne l'aurait
// que par la migration — qui ne tourne qu'une fois, et qu'on pourrait retirer
// un jour en la croyant inutile.
func TestLaTableNeuvePorteLUnicite(t *testing.T) {
	src := lireSource(t, "create_data_base.go")

	debut := strings.Index(src, "CREATE TABLE IF NOT EXISTS did_login")
	if debut < 0 {
		t.Fatal("did_login introuvable dans le schéma")
	}
	fin := strings.Index(src[debut:], ");`")
	if fin < 0 {
		t.Fatal("fin de la définition de did_login introuvable")
	}
	definition := src[debut : debut+fin]

	if !strings.Contains(definition, indexDidLoginUniq) {
		t.Errorf("le CREATE TABLE de did_login ne porte pas %q : une base neuve "+
			"n'aurait l'unicité que par la migration", indexDidLoginUniq)
	}
	for _, colonne := range []string{"d_id_user", "d_id_logiciel"} {
		if !strings.Contains(definition, colonne) {
			t.Errorf("colonne %q absente de la définition", colonne)
		}
	}
}

// Le nom de l'index doit être le MÊME des deux côtés.
//
// `EnsureUniqueIndex` inspecte `information_schema` par ce nom : s'il diffère de
// celui du CREATE TABLE, la migration ne trouve pas l'index d'une base neuve et
// tente de le poser une seconde fois, à chaque démarrage. C'est exactement le
// piège que le test jumeau de `cluster_nodes` décrit.
func TestLeNomDeLIndexEstLeMemeDesDeuxCotes(t *testing.T) {
	src := lireSource(t, "create_data_base.go")
	if !strings.Contains(src, "UNIQUE KEY "+indexDidLoginUniq) {
		t.Errorf("le CREATE TABLE n'emploie pas le nom %q déclaré par la migration",
			indexDidLoginUniq)
	}
}

// LE test du point : plus aucune lecture-puis-écriture sur `did_login`.
//
// On inspecte le TEXTE des requêtes des deux fichiers qui écrivent la table. Un
// `SELECT EXISTS` ou un `COUNT(*)` suivi d'un `INSERT` y est exactement la
// course que l'unicité en base a supprimée — la réintroduire annulerait le
// point sans qu'aucun test de comportement ne le voie.
func TestAucuneLectureAvantEcritureSurDidLogin(t *testing.T) {
	fichiers := map[string]string{
		"AddLoginEntry":       filepath.Join("..", "db_sessions", "add_login_entry.go"),
		"RafraichirConnexion": filepath.Join("..", "db_sessions", "rafraichir_connexion.go"),
	}

	for nom, chemin := range fichiers {
		src := lireSource(t, chemin)

		// Les littéraux de requête uniquement : un commentaire qui RACONTE
		// l'ancienne séquence doit rester permis, et il y en a.
		for _, requete := range litterauxDeRequete(t, chemin) {
			majuscule := strings.ToUpper(requete)
			if !strings.Contains(majuscule, "DID_LOGIN") {
				continue
			}
			if strings.Contains(majuscule, "SELECT EXISTS") || strings.Contains(majuscule, "COUNT(*)") {
				t.Errorf("%s : lecture de did_login avant écriture — la course que "+
					"l'unicité en base a supprimée est de retour :\n%s", nom, requete)
			}
		}

		if !strings.Contains(strings.ToUpper(src), "ON DUPLICATE KEY UPDATE") {
			t.Errorf("%s : aucune écriture en ON DUPLICATE KEY UPDATE", nom)
		}
	}
}

// litterauxDeRequete rend les chaînes littérales d'un fichier.
//
// Par l'arbre syntaxique et non par recherche de texte : c'est ce qui distingue
// une requête d'un commentaire qui la cite, et les commentaires de ce paquet en
// citent beaucoup.
func litterauxDeRequete(t *testing.T, chemin string) []string {
	t.Helper()
	fset := token.NewFileSet()
	fichier, err := parser.ParseFile(fset, chemin, nil, 0)
	if err != nil {
		t.Fatalf("analyse de %s : %v", chemin, err)
	}

	var out []string
	ast.Inspect(fichier, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if ok && lit.Kind == token.STRING {
			out = append(out, lit.Value)
		}
		return true
	})
	return out
}
