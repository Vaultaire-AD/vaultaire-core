package passwordpolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Le point 100 tient à deux choses : la règle elle-même, et le fait qu'AUCUN
// chemin ne la contourne. La première s'éprouve par des cas, la seconde ne peut
// l'être que par inspection du code — d'où le test-sentinelle en fin de fichier.

func exigencesDeTest(longueur int) Exigences {
	return ExigencesPour(longueur, "alice@paris.acme.fr")
}

// LE test du point : ce qui était accepté hier ne l'est plus.
func TestLesMotsDePasseFaiblesSontRefuses(t *testing.T) {
	e := exigencesDeTest(12)

	cas := []struct {
		motDePasse string
		motif      string
	}{
		{"1234", "quatre chiffres — le cas qui a motivé le point"},
		{"", "la chaîne vide"},
		{"azerty", "un classique, et trop court"},
		{"Password1!", "la complexité sans la longueur : il est dans toutes les listes"},
		{"motdepasse123", "assez long, mais c'est « motdepasse »"},
		{"alice2026aaa", "assez long, mais il contient l'identifiant"},
		{"acmeacmeacme", "assez long, mais il contient le domaine"},
		{"vaultaire123", "le nom du produit"},
		{"aaaaaaaaaaaa", "douze caractères, un seul répété"},
		{"  motdepassecorrect  ", "des espaces en bordure : une coquille de copier-coller"},
		{"P@ssw0rd1234", "la substitution de chiffres ne déguise rien"},
	}

	for _, c := range cas {
		if manques := Controler(e, c.motDePasse); len(manques) == 0 {
			t.Errorf("%q accepté — %s", c.motDePasse, c.motif)
		}
	}
}

// Et ce qui est bon passe. Un test de refus seul serait satisfait par une règle
// qui refuse tout.
func TestLesBonsMotsDePassePassent(t *testing.T) {
	e := exigencesDeTest(12)

	cas := []struct {
		motDePasse string
		motif      string
	}{
		{"correcte agrafe batterie", "une phrase de passe : exactement ce qu'on veut encourager"},
		{"Zr7#kLm9vQx2", "douze caractères sans motif"},
		{"jaimebienlesbateauxavoile", "long, sans majuscule ni chiffre — et c'est très bien"},
		{"ZeroDeuxSeptNeufQuatre", "long, sans interdit : la longueur prime"},
	}

	for _, c := range cas {
		if manques := Controler(e, c.motDePasse); len(manques) > 0 {
			t.Errorf("%q refusé (%v) — %s", c.motDePasse, manques, c.motif)
		}
	}
}

// Le message dit CE QUI MANQUE. Un refus muet se contourne en essayant des
// variantes au hasard, donc en finissant sur quelque chose d'à peine acceptable.
func TestLeRefusDitCeQuiManque(t *testing.T) {
	e := exigencesDeTest(12)

	manques := Controler(e, "court")
	if len(manques) == 0 {
		t.Fatal("« court » accepté")
	}
	if !strings.Contains(manques[0], "12") {
		t.Errorf("le message ne dit pas la longueur attendue : %q", manques[0])
	}

	erreur := &ErreurRobustesse{Manques: Controler(e, "alicealicealice")}
	if !strings.Contains(erreur.Error(), "alice") {
		t.Errorf("le message ne nomme pas l'interdit rencontré : %q", erreur.Error())
	}
}

// La longueur se compte en RUNES.
//
// « épée » fait quatre caractères et six octets. Compter en octets rendrait la
// règle plus laxiste pour qui écrit en ASCII et plus stricte pour les autres,
// sans que rien ne le dise à personne.
func TestLaLongueurSeCompteEnCaracteres(t *testing.T) {
	e := Exigences{LongueurMin: 12}

	// Douze caractères accentués : douze runes, vingt-quatre octets.
	douzeAccents := "éééééééééééé"
	if len([]rune(douzeAccents)) != 12 {
		t.Fatalf("échantillon mal formé : %d runes", len([]rune(douzeAccents)))
	}
	// Refusé, mais pour la RÉPÉTITION, pas pour la longueur.
	for _, m := range Controler(e, douzeAccents) {
		if strings.Contains(m, "caractère(s), il en faut") {
			t.Errorf("« %s » compté en octets : %q", douzeAccents, m)
		}
	}

	// Onze caractères accentués : refusé, et cette fois pour la longueur.
	onze := "éàèùâêîôûçé"
	if len([]rune(onze)) != 11 {
		t.Fatalf("échantillon mal formé : %d runes", len([]rune(onze)))
	}
	if len(Controler(e, onze)) == 0 {
		t.Errorf("« %s » accepté alors qu'il fait 11 caractères", onze)
	}
}

// Les interdits propres au compte se déduisent de son nom complet.
//
// C'est le mot de passe qu'un attaquant essaie en DEUXIÈME, juste après
// « password » : il connaît déjà sa cible.
func TestLesInterditsSuiventLeCompte(t *testing.T) {
	e := ExigencesPour(12, "jean.dupont@infra.exemple.fr")

	for _, motDePasse := range []string{
		"jeandupont12", "dupont123456", "infraaaaaaaa", "exemple12345",
	} {
		if len(Controler(e, motDePasse)) == 0 {
			t.Errorf("%q accepté : il reprend un morceau du compte", motDePasse)
		}
	}

	// Le suffixe de domaine à deux lettres n'est PAS un interdit : il apparaît
	// dans trop de mots de passe honnêtes, et le refuser produirait un message
	// incompréhensible.
	if len(Controler(e, "frfrfrfrfrfr")) == 1 &&
		strings.Contains(Controler(e, "frfrfrfrfrfr")[0], "« fr »") {
		t.Error("« fr » traité comme un interdit : un fragment de deux lettres est trop court")
	}
}

// Un fragment court du compte ne devient pas un interdit non plus.
func TestUnCompteTresCourtNInterditPasTout(t *testing.T) {
	e := ExigencesPour(12, "al@a.fr")
	if manques := Controler(e, "correcte agrafe batterie"); len(manques) > 0 {
		t.Errorf("mot de passe correct refusé pour un compte au nom court : %v", manques)
	}
}

// ---------------------------------------------------------------------------
// Le test-sentinelle : le point d'écriture est UNIQUE.
// ---------------------------------------------------------------------------

// racineServeur remonte jusqu'au module.
const racineServeur = "../../.."

// exceptionsHachage nomme les fichiers autorisés à appeler security.Hacher
// ailleurs que dans ce paquet, avec la raison.
var exceptionsHachage = map[string]string{
	// Le réencodage à la connexion remplace une empreinte par une autre SANS
	// que l'utilisateur ait choisi un nouveau mot de passe. Le contrôler
	// refuserait la connexion d'un compte dont le mot de passe était
	// parfaitement acceptable le jour où il l'a choisi — c'est-à-dire
	// enfermerait dehors, au durcissement de la règle, exactement les comptes
	// qu'on cherche à migrer vers argon2id.
	"core/database/db_users/verify_password.go": "réencodage d'une empreinte, sans nouveau mot de passe",

	// Le paquet qui DÉFINIT Hacher, et ses tests.
	"core/global/security/password.go": "définition",

	// Le banc d'essai interne (« vaultaire --test ») éprouve le hachage
	// lui-même : il fabrique des empreintes à partir de vecteurs choisis, dont
	// certains délibérément faibles, et n'écrit rien en base.
	"core/testrunner/run_password.go": "banc d'essai du hachage, aucune écriture en base",
}

// LE test du point : personne ne hache un mot de passe NEUF sans passer par le
// contrôle de robustesse.
//
// # Pourquoi un test de source
//
// La règle est « aucun chemin ne contourne », c'est-à-dire une propriété de
// l'ensemble du module. Un test de comportement vérifierait qu'un chemin donné
// refuse « 1234 » ; celui-ci vérifie qu'il n'existe pas de cinquième façade —
// écrite plus tard, par quelqu'un qui n'aura pas lu ce fichier — qui hacherait
// directement. C'est exactement l'erreur que le point 100 corrige : la règle
// manquait parce que personne n'avait d'endroit où la mettre.
func TestPersonneNeHacheUnMotDePasseNeufSansControle(t *testing.T) {
	fautifs := map[string][]string{}

	err := filepath.Walk(racineServeur, func(chemin string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(chemin, ".go") || strings.HasSuffix(chemin, "_test.go") {
			return nil
		}

		relatif := filepath.ToSlash(strings.TrimPrefix(
			filepath.Clean(chemin), filepath.Clean(racineServeur)+string(filepath.Separator)))

		// Ce paquet est le point d'écriture : c'est lui qui a le droit.
		if strings.HasPrefix(relatif, "core/auth/passwordpolicy/") {
			return nil
		}
		if _, permis := exceptionsHachage[relatif]; permis {
			return nil
		}

		if appels := appelsAHacher(chemin); len(appels) > 0 {
			fautifs[relatif] = appels
		}
		return nil
	})
	if err != nil {
		t.Fatalf("parcours du module : %v", err)
	}

	for fichier, appels := range fautifs {
		t.Errorf("%s appelle %v directement.\n"+
			"  Un mot de passe NEUF passe par passwordpolicy.PreparerNouveauMotDePasse,\n"+
			"  qui contrôle la robustesse avant de hacher (TO-DO 100). Hacher ici crée\n"+
			"  une façade de plus par laquelle « 1234 » entre dans l'annuaire, sans\n"+
			"  qu'aucun test de comportement ne le voie.\n"+
			"  Si ce fichier RÉENCODE une empreinte existante sans nouveau mot de passe,\n"+
			"  ajoutez-le à exceptionsHachage avec sa raison.",
			fichier, appels)
	}
}

// appelsAHacher rend les appels à security.Hacher d'un fichier.
//
// Par l'arbre syntaxique et non par recherche de texte : les commentaires de ce
// dépôt citent « security.Hacher » à plusieurs endroits pour expliquer le
// chemin, et un test qui se déclenche sur un commentaire finit désactivé.
func appelsAHacher(chemin string) []string {
	fset := token.NewFileSet()
	fichier, err := parser.ParseFile(fset, chemin, nil, 0)
	if err != nil {
		return nil
	}

	var out []string
	ast.Inspect(fichier, func(n ast.Node) bool {
		appel, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := appel.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		paquet, ok := sel.X.(*ast.Ident)
		if !ok || paquet.Name != "security" {
			return true
		}
		if sel.Sel.Name == "Hacher" || sel.Sel.Name == "HacherAvecSel" {
			out = append(out, "security."+sel.Sel.Name)
		}
		return true
	})
	return out
}
