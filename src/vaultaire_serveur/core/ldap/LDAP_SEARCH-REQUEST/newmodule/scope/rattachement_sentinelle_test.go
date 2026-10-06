package scope

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LA SENTINELLE DU POINT 120.
//
// Ce que la règle d'autorisation fait de `Rattachements` s'éprouve dans
// newmodule/security ; ce que `Domaines()` en rend s'éprouve dans candidate. Mais
// le défaut de la première version du correctif n'était ni l'un ni l'autre :
// c'était le CÂBLAGE — quelle valeur est déposée dans ce champ, ici, au moment où
// l'entrée est construite.
//
// `UserEntry.BaseDN` porte le domaine DEMANDÉ par le client. L'écrire dans
// `Rattachements` autorise tout compte par construction : le filtre ne voit alors
// que le domaine qui vient d'être autorisé. C'est passé une première fois, et
// aucun test de comportement ne l'a vu — ceux de la règle passaient tous.
//
// Une sentinelle donc : elle lit le code de ce paquet et refuse les deux formes
// du défaut. Elle est le seul test capable d'attraper un retour en arrière ici,
// puisqu'éprouver le résolveur pour de bon demanderait une base.

const champRattachements = "Rattachements"

// Les identifiants qui portent, dans ce paquet, le domaine DEMANDÉ par le
// client — donc ceux qu'un rattachement ne doit jamais valoir.
var identifiantsInterdits = map[string]string{
	"domain":       "variable de boucle sur les domaines DEMANDÉS",
	"baseDN":       "domaine déduit du baseObject du client",
	"baseObject":   "base demandée par le client",
	"domaineDuDN":  "domaine reconstruit depuis le DN demandé",
	"expectedDN":   "DN demandé par le client",
	"groupDomain":  "domaine demandé, transmis au chargement",
	"groupDomains": "domaines demandés, transmis au chargement",
}

func TestChaqueUserEntryRenseigneSesRattachements(t *testing.T) {
	for chemin, fichier := range fichiersDuPaquet(t) {
		ast.Inspect(fichier, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !estUneUserEntryConstruite(lit) {
				return true
			}

			champs := champsAssignes(lit)
			if _, présent := champs[champRattachements]; !présent {
				t.Errorf("%s : une UserEntry est construite sans %s.\n"+
					"Une entrée sans rattachement est ÉCARTÉE par le contrôle d'accès : "+
					"le compte deviendrait invisible. Renseignez les domaines des groupes "+
					"par lesquels le compte a été trouvé.", chemin, champRattachements)
			}
			return true
		})
	}
}

func TestUnRattachementNEstJamaisLeDomaineDemande(t *testing.T) {
	for chemin, fichier := range fichiersDuPaquet(t) {
		ast.Inspect(fichier, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !estUneUserEntryConstruite(lit) {
				return true
			}

			valeur, présent := champsAssignes(lit)[champRattachements]
			if !présent {
				return true // signalé par le test précédent
			}

			for _, nom := range identifiantsUtilises(valeur) {
				if raison, interdit := identifiantsInterdits[nom]; interdit {
					t.Errorf("%s : %s vaut « %s » — %s.\n"+
						"Le contrôle d'accès s'autoriserait lui-même : le filtre ne verrait "+
						"que le domaine qui vient d'être autorisé à l'entrée, et tout compte "+
						"d'un sous-domaine ressortirait. C'est le défaut du point 120.",
						chemin, champRattachements, nom, raison)
				}
			}
			return true
		})
	}
}

// Et le champ qui compose le DN, lui, reste distinct : si les deux finissaient
// par recevoir la même chose, les deux tests ci-dessus passeraient encore.
func TestLeDomaineDuDNEtLesRattachementsRestentDistincts(t *testing.T) {
	for chemin, fichier := range fichiersDuPaquet(t) {
		ast.Inspect(fichier, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !estUneUserEntryConstruite(lit) {
				return true
			}

			champs := champsAssignes(lit)
			base, aBase := champs["BaseDN"]
			ratt, aRatt := champs[champRattachements]
			if !aBase || !aRatt {
				return true
			}
			if rendu(base) == rendu(ratt) {
				t.Errorf("%s : BaseDN et %s reçoivent la même expression (« %s »).\n"+
					"Le premier compose le DN, le second décide des droits, et ils "+
					"diffèrent : ToRootDN ne garde que les deux derniers labels, donc un "+
					"compte de admin.enov.local et un compte de enov.local ont le MÊME DN.",
					chemin, champRattachements, rendu(base))
			}
			return true
		})
	}
}

// LA SENTINELLE DU POINT 132.
//
// `memberOf` n'est filtré que si chaque groupe y entre avec SON domaine ; et
// `member` n'a rien à filtrer que parce qu'un groupe est jugé sur son domaine
// PROPRE (voir candidate.GroupEntry.Restreinte). Les deux tiennent à la même
// chose : que le domaine déposé soit celui que la BASE a rendu pour le groupe
// — un champ `DomainName` —, jamais celui que le client a demandé.
//
// Avec le domaine demandé, tout groupe porterait le domaine qui vient d'être
// autorisé : rien ne serait retiré de `memberOf`, et un groupe de sous-domaine
// passerait le contrôle d'accès. C'est le défaut du point 120, par un autre
// champ, et aucun test de comportement ne le verrait.

func estUnLitteral(typ ast.Expr, nom string) bool {
	sel, ok := typ.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != nom {
		return false
	}
	paquet, ok := sel.X.(*ast.Ident)
	return ok && paquet.Name == "candidate"
}

// vientDeLaBase dit si une expression est un champ `DomainName` — `g.DomainName`,
// `group.DomainName`.
func vientDeLaBase(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "DomainName"
}

func TestLeDomaineDUneAppartenanceEstCeluiDuGroupe(t *testing.T) {
	vues := 0
	for chemin, fichier := range fichiersDuPaquet(t) {
		ast.Inspect(fichier, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || len(lit.Elts) == 0 || !estUnLitteral(lit.Type, "Appartenance") {
				return true
			}
			vues++
			valeur, présent := champsAssignes(lit)["Domaine"]
			switch {
			case !présent:
				t.Errorf("%s : une Appartenance est construite sans Domaine.\n"+
					"Elle sera écartée de memberOf pour tout le monde : le groupe "+
					"disparaîtrait de l'annuaire de ses propres membres.", chemin)
			case !vientDeLaBase(valeur):
				t.Errorf("%s : le Domaine d'une Appartenance vaut « %s », pas le DomainName "+
					"du groupe lu en base.\nAvec le domaine demandé par le client, rien ne "+
					"serait retiré de memberOf — le défaut du point 132.", chemin, rendu(valeur))
			}
			return true
		})
	}
	if vues == 0 {
		t.Fatal("aucune Appartenance construite dans ce paquet : la sentinelle ne garde rien")
	}
}

func TestLeDomaineDUnGroupeEstLeSien(t *testing.T) {
	vues := 0
	for chemin, fichier := range fichiersDuPaquet(t) {
		ast.Inspect(fichier, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || len(lit.Elts) == 0 || !estUnLitteral(lit.Type, "GroupEntry") {
				return true
			}
			vues++
			valeur, présent := champsAssignes(lit)["BaseDN"]
			if !présent || !vientDeLaBase(valeur) {
				t.Errorf("%s : le BaseDN d'une GroupEntry n'est pas le DomainName du groupe "+
					"lu en base.\nC'est sur lui que le contrôle d'accès juge le groupe, et "+
					"c'est ce qui rend `member` lisible sans filtrage : avec le domaine "+
					"demandé, un groupe de sous-domaine sortirait avec la liste de ses membres.",
					chemin)
			}
			return true
		})
	}
	if vues == 0 {
		t.Fatal("aucune GroupEntry construite dans ce paquet : la sentinelle ne garde rien")
	}
}

func fichiersDuPaquet(t *testing.T) map[string]*ast.File {
	t.Helper()

	entrées, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("lecture du paquet : %v", err)
	}

	fset := token.NewFileSet()
	fichiers := make(map[string]*ast.File)
	for _, e := range entrées {
		nom := e.Name()
		if e.IsDir() || !strings.HasSuffix(nom, ".go") || strings.HasSuffix(nom, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", nom), nil, 0)
		if err != nil {
			t.Fatalf("analyse de %s : %v", nom, err)
		}
		fichiers[nom] = f
	}
	if len(fichiers) == 0 {
		t.Fatal("aucun fichier analysé : la sentinelle ne garde rien")
	}
	return fichiers
}

// estUneUserEntryConstruite écarte les littéraux VIDES — `candidate.UserEntry{}`,
// qui accompagne un « false » de retour et ne décrit aucune entrée. Les exiger
// renseignés obligerait à écrire un rattachement bidon sur un chemin d'erreur,
// c'est-à-dire exactement le genre de valeur de complaisance que cette sentinelle
// existe pour empêcher.
func estUneUserEntryConstruite(lit *ast.CompositeLit) bool {
	return len(lit.Elts) > 0 && estUserEntry(lit.Type)
}

func estUserEntry(typ ast.Expr) bool {
	sel, ok := typ.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "UserEntry" {
		return false
	}
	paquet, ok := sel.X.(*ast.Ident)
	return ok && paquet.Name == "candidate"
}

func champsAssignes(lit *ast.CompositeLit) map[string]ast.Expr {
	champs := make(map[string]ast.Expr, len(lit.Elts))
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if clé, ok := kv.Key.(*ast.Ident); ok {
			champs[clé.Name] = kv.Value
		}
	}
	return champs
}

// identifiantsUtilises rend tous les noms qui apparaissent dans une expression :
// `domain`, `[]string{domain}` et `domainesDe(domain)` doivent être vus pareil.
func identifiantsUtilises(e ast.Expr) []string {
	var noms []string
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			noms = append(noms, id.Name)
		}
		return true
	})
	return noms
}

func rendu(e ast.Expr) string {
	return strings.Join(identifiantsUtilises(e), ".")
}
