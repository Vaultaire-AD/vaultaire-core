package logs

// Sentinelle de la TO-DO 153 : plus d'écriture directe sur la sortie standard
// en dehors des endroits dont c'est le métier.
//
// Un fmt.Println ou un log.Printf dans le core n'arrive ni dans le journal, ni
// au syslog, ni à l'administrateur qui lance une commande à distance : il part
// sur la console du conteneur, que personne ne lit. Un log.Fatal hors du
// démarrage est pire : il arrête tout le core, sans trace au journal.
//
// Le test parcourt le module avec go/parser (les commentaires ne comptent
// donc pas) et refuse, hors des dossiers autorisés :
//   - fmt.Print, fmt.Printf, fmt.Println ;
//   - toute référence à os.Stdout ou os.Stderr ;
//   - toute fonction du paquet standard « log » (quel que soit son alias) ;
//   - les fonctions natives print et println.
//
// Dossiers autorisés : core/command et core/testrunner (ils construisent la
// sortie de la CLI), main, et core/logs lui-même (la rotation ne peut pas se
// journaliser elle-même). Seule exception ailleurs : log.Fatal/Fatalf dans
// les trois fichiers d'AMORÇAGE, où s'arrêter est voulu — un core sans schéma,
// sans compte d'amorçage ou sans certificat web ne doit pas démarrer.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var dossiersAutorises = []string{"core/command/", "core/testrunner/", "main/", "core/logs/"}

var fatalAmorcage = map[string]bool{
	"core/database/db_schema/create_data_base.go":          true,
	"core/database/db_schema/create_default_admin_user.go": true,
	"core/web_serveur/startWEBserver.go":                   true,
}

// ecrituresDirectes rend, pour un fichier source, les écritures interdites
// sous la forme « ligne: appel ».
func ecrituresDirectes(fset *token.FileSet, f *ast.File, chemin string) []string {
	// Nom local de chaque import : « log » peut être aliasé.
	noms := map[string]string{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		nom := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			nom = imp.Name.Name
		}
		noms[nom] = p
	}
	var trouves []string
	signaler := func(n ast.Node, quoi string) {
		trouves = append(trouves, strconv.Itoa(fset.Position(n.Pos()).Line)+": "+quoi)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			if !ok || id.Obj != nil { // id.Obj != nil : variable locale, pas un paquet
				return true
			}
			switch noms[id.Name] {
			case "fmt":
				if x.Sel.Name == "Print" || x.Sel.Name == "Printf" || x.Sel.Name == "Println" {
					signaler(x, "fmt."+x.Sel.Name)
				}
			case "os":
				if x.Sel.Name == "Stdout" || x.Sel.Name == "Stderr" {
					signaler(x, "os."+x.Sel.Name)
				}
			case "log":
				estFatal := strings.HasPrefix(x.Sel.Name, "Fatal")
				if !(estFatal && fatalAmorcage[chemin]) {
					signaler(x, "log."+x.Sel.Name)
				}
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Obj == nil && (id.Name == "print" || id.Name == "println") {
				signaler(x, id.Name)
			}
		}
		return true
	})
	return trouves
}

func TestAucuneEcritureDirecteHorsJournal(t *testing.T) {
	racine := filepath.Join("..", "..")
	fset := token.NewFileSet()
	analyses := 0
	err := filepath.WalkDir(racine, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(racine, p)
		rel = filepath.ToSlash(rel)
		for _, a := range dossiersAutorises {
			if strings.HasPrefix(rel, a) {
				return nil
			}
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		analyses++
		for _, e := range ecrituresDirectes(fset, f, rel) {
			t.Errorf("%s:%s — passer par logs.Write_Log / Write_LogCode, ou rendre une erreur", rel, e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if analyses < 100 {
		t.Fatalf("seulement %d fichiers analysés depuis %s : la racine du module a-t-elle bougé ?", analyses, racine)
	}
}

// La sentinelle elle-même : chaque forme interdite est vue, et ce qui est
// permis ne l'est pas. Sans ce test, un ecrituresDirectes qui ne trouve plus
// rien laisserait passer le test précédent en silence.
func TestSentinelleEcritureDirecteVoitChaqueForme(t *testing.T) {
	source := `package x
import (
	"fmt"
	"os"
	stdlog "log"
)
func f(w *os.File) {
	fmt.Println("a")
	fmt.Printf("b")
	fmt.Print("c")
	fmt.Fprintln(os.Stderr, "d")
	stdlog.Printf("e")
	stdlog.Fatal("f")
	println("g")
	// fmt.Println("commentaire : ignoré")
	_ = fmt.Sprintf("permis")
	fmt.Fprintln(w, "permis : un Writer reçu")
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(ecrituresDirectes(fset, f, "core/x/x.go"), "|")
	want := "8: fmt.Println|9: fmt.Printf|10: fmt.Print|11: os.Stderr|12: stdlog.Printf|13: stdlog.Fatal|14: println"
	// Le nom affiché est celui du paquet, pas l'alias.
	want = strings.ReplaceAll(want, "stdlog.", "log.")
	if got != want {
		t.Fatalf("trouvé %q, attendu %q", got, want)
	}

	// log.Fatal n'est permis que dans un fichier d'amorçage.
	got = strings.Join(ecrituresDirectes(fset, f, "core/web_serveur/startWEBserver.go"), "|")
	if strings.Contains(got, "log.Fatal") {
		t.Fatalf("log.Fatal refusé dans un fichier d'amorçage : %q", got)
	}
	if !strings.Contains(got, "log.Printf") {
		t.Fatalf("log.Printf accepté dans un fichier d'amorçage : %q", got)
	}
}
