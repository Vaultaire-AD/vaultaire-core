package sessionmgr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// La règle que ce fichier ÉNONCE — TO-DO 106.
//
// # Ce qu'il y a à énoncer
//
// `vaultaire` désigne deux choses dans ce produit : le compte sous lequel chaque
// machine du parc ouvre son tunnel, et le compte d'annuaire membre du groupe
// superadmin, porteur de `vaultaire_all`. C'est la MÊME ligne de la table
// `users`.
//
// Ce que cela vaut aujourd'hui : chaque machine ouvre une ligne `did_login` au
// nom du superadmin, et une session Ducky authentifiée porte
// `Username == "vaultaire"`. Ce qui protège le produit est que RIEN n'accorde de
// droit à partir de ce champ : le contrôle d'accès des trames passe par
// `clienttype.MayEmit`, qui raisonne sur le TYPE du programme, jamais sur le nom
// du compte de la session.
//
// C'est une propriété, et rien ne l'énonçait. Une lecture de droits ajoutée un
// jour à partir de `Session.Username` — le geste le plus naturel du monde —
// accorderait tout à n'importe quelle machine du parc, sans qu'aucun test ne
// tombe.
//
// # Pourquoi un test de SOURCE et pas de comportement
//
// Un test de comportement vérifierait qu'un chemin donné refuse. Celui-ci
// vérifie qu'aucun chemin n'existe : c'est une propriété de l'ensemble du
// paquet réseau, et seule l'inspection du code peut la porter.
//
// Il échouera le jour où quelqu'un écrira cette lecture. C'est exactement ce
// qu'on lui demande — et le message lui dira pourquoi.

// paquetsReseau sont les paquets qui traitent une trame et voient donc une
// session authentifiée.
var paquetsReseau = []string{
	"../authentification",
	"../gpo_manager",
	"../host_handler",
	"../revocation_manager",
	"../serviceauth",
	"../trames_manager",
}

// lecturesDeDroits nomme les fonctions qui accordent, ou qui servent à accorder.
//
// Les nommer plutôt que chercher « permission » : le mot apparaît dans des
// commentaires, des messages et des noms de table, et un test qui se déclenche
// sur un commentaire finit par être désactivé.
var lecturesDeDroits = []string{
	"CheckPermissionsAllDomains",
	"CheckPermissionsMultipleDomains",
	"HasActionAnywhere",
	"DomainsWhereAllowed",
	"IsSuperadmin",
	"GroupesContiennentLeGroupeProtege",
	"Get_Groups_ID_By_Username",
}

// champsDeSession sont les champs d'une session dont le contenu est le NOM
// annoncé par le pair.
var champsDeSession = []string{"Username"}

func TestAucunDroitNeSeDeduitDuNomDUneSessionDucky(t *testing.T) {
	for _, paquet := range paquetsReseau {
		fichiers, err := fichiersGo(paquet)
		if err != nil {
			// Un paquet renommé ou déplacé : on le dit plutôt que de se taire,
			// sinon la couverture se réduit sans que personne ne le voie.
			t.Errorf("paquet %s illisible : %v — la règle n'y est plus vérifiée", paquet, err)
			continue
		}

		for _, chemin := range fichiers {
			if strings.HasSuffix(chemin, "_test.go") {
				continue
			}
			signaler(t, chemin)
		}
	}
}

// signaler cherche, dans un fichier, un appel de lecture de droits dont un
// argument descend d'un champ de nom de session.
func signaler(t *testing.T, chemin string) {
	t.Helper()

	fset := token.NewFileSet()
	fichier, err := parser.ParseFile(fset, chemin, nil, 0)
	if err != nil {
		t.Errorf("analyse de %s : %v", chemin, err)
		return
	}

	ast.Inspect(fichier, func(n ast.Node) bool {
		appel, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		nom := nomAppele(appel.Fun)
		if !contient(lecturesDeDroits, nom) {
			return true
		}
		for _, arg := range appel.Args {
			if champ := champDeSessionUtilise(arg); champ != "" {
				t.Errorf(
					"%s : %s reçoit %s.\n"+
						"  Le nom d'utilisateur d'une session Ducky est celui que le PAIR a\n"+
						"  annoncé, et pour une machine du parc il vaut « vaultaire » — le compte\n"+
						"  du groupe superadmin. En déduire un droit accorde tout à n'importe\n"+
						"  quelle machine enrôlée.\n"+
						"  Le contrôle des trames passe par clienttype.MayEmit, qui raisonne sur\n"+
						"  le TYPE du programme. Voir TO-DO 106.",
					posLisible(fset, appel.Pos()), nom, champ)
			}
		}
		return true
	})
}

// champDeSessionUtilise rend le champ de session employé dans une expression,
// ou une chaîne vide.
func champDeSessionUtilise(e ast.Expr) string {
	var trouve string
	ast.Inspect(e, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !contient(champsDeSession, sel.Sel.Name) {
			return true
		}
		// Le receveur doit ressembler à une session : `sess.Username`,
		// `duckysession.Username`, `trames_content.Username`.
		receveur := strings.ToLower(nomAppele(sel.X))
		if strings.Contains(receveur, "sess") || strings.Contains(receveur, "trame") {
			trouve = receveur + "." + sel.Sel.Name
			return false
		}
		return true
	})
	return trouve
}

func nomAppele(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

func contient(liste []string, valeur string) bool {
	for _, v := range liste {
		if v == valeur {
			return true
		}
	}
	return false
}

func fichiersGo(repertoire string) ([]string, error) {
	var out []string
	err := filepath.Walk(repertoire, func(chemin string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(chemin, ".go") {
			out = append(out, chemin)
		}
		return nil
	})
	return out, err
}

func posLisible(fset *token.FileSet, p token.Pos) string {
	pos := fset.Position(p)
	return filepath.Base(filepath.Dir(pos.Filename)) + "/" + filepath.Base(pos.Filename) +
		":" + itoa(pos.Line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var chiffres []byte
	for n > 0 {
		chiffres = append([]byte{byte('0' + n%10)}, chiffres...)
		n /= 10
	}
	return string(chiffres)
}

// Le pendant positif : le compte d'amorçage est bien celui du tunnel machine,
// et les deux constantes doivent rester d'accord. Si `CompteMachine` changeait
// sans que `isprotected.ProtectedUsername` suive, la règle ci-dessus
// continuerait de passer en ne protégeant plus rien.
func TestLeCompteMachineEstBienLeCompteDAmorcage(t *testing.T) {
	if CompteMachine != "vaultaire" {
		t.Errorf("CompteMachine = %q : la valeur doit rester celle du compte "+
			"d'amorçage (isprotected.ProtectedUsername), sans quoi les refus posés "+
			"sur 03_01 et 08_01 ne visent plus le bon nom", CompteMachine)
	}
}
