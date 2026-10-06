package gpo

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// La CLASSE d'erreur du point 135, et non son occurrence.
//
// # Ce qui s'est passé
//
// L'inventaire reposait sur une affirmation écrite en tête de manifest.go :
// « toutes les écritures passent par writeSystemFile, il n'existe aucun autre
// chemin — vérifié ». Elle était vraie le jour où elle a été écrite. Puis le
// scope utilisateur a reçu son propre chemin d'écriture, pour une excellente
// raison (TO-DO 97), et personne n'a relu l'affirmation. Les fichiers d'un
// `HOME` ont cessé d'entrer dans l'inventaire sans qu'aucun test ne bouge.
//
// Corriger l'appel manquant ferme l'occurrence. La prochaine fonction qui
// écrira sous un `HOME` par un autre moyen rouvrira le défaut à l'identique.
//
// # Ce que ce test interdit
//
// À toute fonction d'appliqueur qui CONNAÎT le scope utilisateur :
//
//   - d'inscrire dans l'inventaire du cycle MACHINE — les formes nues
//     `writeSystemFile`, `removeSystemFile`, `recordCheck`. L'entrée d'un compte
//     y serait attribuée à un module de la machine, ou à personne ;
//   - de toucher au système de fichiers par un CHEMIN — `os.Remove`,
//     `os.WriteFile`, `os.ReadFile`, `readFileIfExists` et leurs voisins. Sous un
//     `HOME`, un chemin se remplace entre deux appels : c'est le point 97, et
//     les deux portes que le 135 a dû fermer en plus (lecture et retrait).
//
// Les formes permises inscrivent d'elles-mêmes dans l'inventaire du bon cycle :
// `writeUserFile`, `removeUserFile`, `writeUserBlock`, `removeUserBlock`,
// `readUserFile`, `ctx.writeSystemFile`, `ctx.removeSystemFile`,
// `ctx.recordCheck`.
//
// # Les exceptions sont nommées
//
// Une fonction qui a une raison de déroger est inscrite ci-dessous, AVEC cette
// raison. Une exception ajoutée sans la relire se voit dans la revue ; un appel
// ajouté dans une fonction non listée fait échouer le test.

// appelsDeroges : fonction → appels permis malgré la règle, et pourquoi.
var appelsDeroges = map[string]map[string]string{
	"applyDirectory": {
		"os.MkdirAll": "branche du scope MACHINE, gardée par ctx.Scope : /etc n'est pas sous le contrôle d'un utilisateur",
		"os.Chmod":    "même branche",
		"preparerRepertoireUtilisateur": "un répertoire n'entre pas à l'inventaire : seuls les fichiers et les " +
			"retraits y entrent, côté machine comme ici",
	},
	"applyUserGitConfig": {
		"os.MkdirTemp": "répertoire de travail privé à root, hors du HOME : c'est ce qui évite de lancer git sous le HOME",
		"os.WriteFile": "écrit la COPIE de travail, dans ce répertoire privé",
		"os.ReadFile":  "relit la COPIE de travail",
		"os.RemoveAll": "retire le répertoire de travail privé",
		"ecrireFichierUtilisateur": ".gitconfig appartient à la personne et Vaultaire n'y tient qu'une clé : " +
			"rien n'est inscrit, la clé n'a pas encore de vérificateur (TO-DO 163)",
	},
	"ensureProfileHook": {
		"retirerSousHome": "ménage d'un fichier inerte laissé par une version antérieure : ce n'est pas une politique",
	},

	// Les quatre entonnoirs : ce sont EUX qui inscrivent, juste après.
	"writeUserFile":   {"ecrireFichierUtilisateur": "entonnoir : inscrit l'écriture"},
	"writeUserBlock":  {"ecrireFichierUtilisateur": "entonnoir : inscrit le bloc"},
	"removeUserFile":  {"retirerSousHome": "entonnoir : inscrit l'absence"},
	"removeUserBlock": {"retirerSousHome": "entonnoir : inscrit l'absence du bloc"},
}

// fonctionsAttendues doivent TOUTES être reconnues comme connaissant le scope
// utilisateur. Si l'une ne l'est plus, c'est la détection qui est devenue
// aveugle, et le test ne garde plus rien.
var fonctionsAttendues = []string{
	"applyFileDeploy", "applyDirectory", "applyFileACL",
	"applyUserEnv", "ensureProfileHook", "applyUserCron",
	"applyUserGroupMembership", "applyUserShell", "applyUserPasswordPolicy",
	"applyUserSSHClientConfig", "applyUserGitConfig", "applyUserResourceLimits",
	"writeUserFile", "removeUserFile", "writeUserBlock", "removeUserBlock", "readUserFile",
}

var inscriptionsMachine = map[string]bool{
	"writeSystemFile": true, "removeSystemFile": true, "recordCheck": true,
}

// primitivesSansInscription écrivent ou retirent sous un `HOME` par la descente
// sûre, mais n'inscrivent RIEN. Les appeler directement, c'est exactement le
// défaut du 135 : un fichier déposé que le scan ne connaîtra jamais. Seuls les
// entonnoirs y ont droit — et les rares gestes qui ne sont pas une politique.
var primitivesSansInscription = map[string]bool{
	"ecrireFichierUtilisateur": true, "retirerSousHome": true, "preparerRepertoireUtilisateur": true,
}

var accesParChemin = map[string]bool{
	"os.Remove": true, "os.RemoveAll": true, "os.WriteFile": true, "os.ReadFile": true,
	"os.Create": true, "os.Open": true, "os.OpenFile": true, "os.Rename": true,
	"os.Symlink": true, "os.Link": true, "os.Chmod": true, "os.Chown": true, "os.Lchown": true,
	"os.Mkdir": true, "os.MkdirAll": true, "os.MkdirTemp": true, "os.Truncate": true,
	"readFileIfExists": true, "restoreOrRemove": true,
}

func TestUnAppliqueurDuScopeUtilisateurNEcritQueParLesFormesSures(t *testing.T) {
	fichiers, err := filepath.Glob("appliers_*.go")
	if err != nil || len(fichiers) == 0 {
		t.Fatalf("aucun fichier d'appliqueur trouve : %v", err)
	}

	reconnues := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		arbre, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("%s : %v", f, err)
		}
		for _, decl := range arbre.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			if !connaitLeScopeUtilisateur(fn) {
				continue
			}
			reconnues[fn.Name.Name] = true
			deroges := appelsDeroges[fn.Name.Name]

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				appel, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				nom := nomDAppel(appel)
				if nom == "" {
					return true
				}
				position := fset.Position(appel.Pos())
				switch {
				case inscriptionsMachine[nom]:
					t.Errorf("%s : %s appelle %s(…), qui inscrit dans l'inventaire du cycle MACHINE. "+
						"Une fonction qui connait le scope utilisateur emploie ctx.%s(…), ou la forme "+
						"« User » correspondante", position, fn.Name.Name, nom, nom)
				case primitivesSansInscription[nom]:
					if _, permis := deroges[nom]; permis {
						return true
					}
					t.Errorf("%s : %s appelle %s(…), qui ecrit sous un HOME SANS rien inscrire a "+
						"l'inventaire — c'est le defaut du point 135. Passer par writeUserFile, "+
						"writeUserBlock, removeUserFile ou removeUserBlock", position, fn.Name.Name, nom)
				case accesParChemin[nom]:
					if _, permis := deroges[nom]; permis {
						return true
					}
					t.Errorf("%s : %s appelle %s(…) : sous un HOME, un chemin se remplace entre deux "+
						"appels (TO-DO 97, 135). Passer par writeUserFile, removeUserFile, readUserFile, "+
						"writeUserBlock — ou inscrire une derogation motivee dans appelsDeroges",
						position, fn.Name.Name, nom)
				}
				return true
			})
		}
	}

	var manquantes []string
	for _, nom := range fonctionsAttendues {
		if !reconnues[nom] {
			manquantes = append(manquantes, nom)
		}
	}
	sort.Strings(manquantes)
	if len(manquantes) > 0 {
		t.Errorf("fonctions du scope utilisateur que ce test ne reconnait plus : %v — "+
			"la detection est devenue aveugle, il ne garde plus rien pour elles", manquantes)
	}

	// Une dérogation pour une fonction qui n'existe plus est une ligne morte,
	// et le jour où le nom resservira elle s'appliquera à autre chose.
	for nom := range appelsDeroges {
		if !reconnues[nom] {
			t.Errorf("derogation inscrite pour %s, qui n'est plus une fonction du scope utilisateur", nom)
		}
	}
}

// connaitLeScopeUtilisateur dit si une fonction manipule le compte ou son
// dossier : elle lit ctx.Username ou ctx.HomeDir, compare à ScopeUser, ou
// développe le marqueur %h.
func connaitLeScopeUtilisateur(fn *ast.FuncDecl) bool {
	trouve := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if base, ok := v.X.(*ast.Ident); ok && base.Name == "ctx" &&
				(v.Sel.Name == "Username" || v.Sel.Name == "HomeDir") {
				trouve = true
			}
		case *ast.Ident:
			if v.Name == "ScopeUser" || v.Name == "expandHome" || v.Name == "idsDuCompte" {
				trouve = true
			}
		}
		return !trouve
	})
	return trouve
}

// nomDAppel rend « f » pour f(…) et « paquet.F » pour paquet.F(…). Un appel de
// méthode sur le contexte — ctx.writeSystemFile — rend « ctx.writeSystemFile »,
// qui n'est dans aucune des deux listes : c'est la forme permise.
func nomDAppel(appel *ast.CallExpr) string {
	switch f := appel.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if base, ok := f.X.(*ast.Ident); ok {
			return base.Name + "." + f.Sel.Name
		}
	}
	return ""
}
