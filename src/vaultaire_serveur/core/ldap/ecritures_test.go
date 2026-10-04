package ldap

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// LA SENTINELLE DU JOURNAL D'OPÉRATION — TO-DO 145.
//
// La ligne d'une opération porte le code rendu au client et le nombre
// d'entrées envoyées. Ni l'un ni l'autre ne sont déduits : ce sont les
// fonctions qui ÉCRIVENT sur la connexion qui les notent, au moment où elles le
// font (ldapjournal.Resultat, ldapjournal.EntreeEnvoyee).
//
// Le revers : une fonction de réponse ajoutée demain, qui écrirait sur la
// connexion sans rien noter, donnerait des lignes « sans réponse » pour des
// opérations auxquelles le serveur a bel et bien répondu — et l'on chercherait
// un client bloqué qui ne l'est pas. Aucun test de comportement ne le verrait,
// la réponse étant correcte.
//
// Ce test lit donc le code du paquet : toute fonction qui écrit sur une
// connexion doit le dire au journal.

// ecritSurUneConnexion reconnaît `conn.Write(…)` et `c.Write(…)` — les deux
// noms qu'une connexion porte dans ce paquet.
func ecritSurUneConnexion(n ast.Node) bool {
	appel, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := appel.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Write" {
		return false
	}
	recepteur, ok := sel.X.(*ast.Ident)
	return ok && (recepteur.Name == "conn" || recepteur.Name == "c")
}

// noteAuJournal reconnaît `ldapjournal.Resultat(…)` et
// `ldapjournal.EntreeEnvoyee(…)`.
func noteAuJournal(n ast.Node) bool {
	appel, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := appel.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	paquet, ok := sel.X.(*ast.Ident)
	return ok && paquet.Name == "ldapjournal" &&
		(sel.Sel.Name == "Resultat" || sel.Sel.Name == "EntreeEnvoyee")
}

func TestTouteEcritureSurUneConnexionEstNoteeAuJournal(t *testing.T) {
	trouvées := 0
	err := filepath.WalkDir(".", func(chemin string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(chemin, ".go") || strings.HasSuffix(chemin, "_test.go") {
			return nil
		}
		fichier, err := parser.ParseFile(token.NewFileSet(), chemin, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range fichier.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var ecrit, note bool
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ecrit = ecrit || ecritSurUneConnexion(n)
				note = note || noteAuJournal(n)
				return true
			})
			if !ecrit {
				continue
			}
			trouvées++
			if !note {
				t.Errorf("%s : %s écrit sur la connexion sans le noter au journal.\n"+
					"La ligne de l'opération dirait « sans réponse » alors que le client a reçu "+
					"la sienne. Appelez ldapjournal.Resultat (réponse) ou "+
					"ldapjournal.EntreeEnvoyee (entrée de recherche).", chemin, fn.Name.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Garde-fou du garde-fou : si la reconnaissance ne trouvait plus rien — un
	// paramètre renommé —, le test passerait à vide.
	if trouvées < 7 {
		t.Fatalf("%d fonction(s) d'écriture reconnue(s), il y en a au moins 7 : "+
			"le test ne voit plus ce qu'il doit surveiller", trouvées)
	}
}
