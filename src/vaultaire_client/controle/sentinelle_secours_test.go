package controle

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// La porte de secours du produit — TO-DO 112, point 4.
//
// # Ce qui est gardé ici
//
// Les piles PAM de Vaultaire meurent quand le module ne joint pas l'agent
// (`default=die`). Une seule chose garde alors la machine joignable : pour un
// compte HORS du domaine — root, un compte local — le module rend `PAM_IGNORE`,
// la pile écrit `ignore=ignore`, et l'authentification continue vers
// `system-auth`. C'est par là qu'on entre réparer une machine dont l'agent est
// mort.
//
// Cette porte tient à trois endroits qui ne se connaissent pas : le code C du
// module, le contrôle `[...]` de la pile, et la ligne qui la suit. Aucun
// compilateur ne les relie, et il n'existe pas de « pam -t » : une pile fausse
// ne se découvre qu'en tentant de se connecter — donc trop tard, et sur la
// machine où plus personne ne peut entrer.
//
// Ces tests échouent si un fichier a été DÉPLACÉ : une sentinelle qui se tait
// quand elle ne trouve plus ce qu'elle garde ne garde rien.

const (
	scriptDInstallation = "../../../automatisation/auto_deployements/rocky.sh"
	dossierDesModules   = "../pam_module/"
)

// modulesVaultaire : les modules d'AUTHENTIFICATION que posent les piles.
var modulesVaultaire = []string{"pam_login_custom_module.so", "pam_ssh_auth_module.so"}

func lire(t *testing.T, chemin string) string {
	t.Helper()
	brut, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("%s illisible (%v) : le fichier a-t-il été déplacé ? Cette sentinelle doit le suivre.", chemin, err)
	}
	return string(brut)
}

// pilesPAM extrait du script les piles qu'il écrit : nom de la pile → lignes.
func pilesPAM(t *testing.T) map[string][]string {
	t.Helper()
	script := lire(t, scriptDInstallation)
	debut := regexp.MustCompile(`cat > /etc/pam\.d/([a-z-]+) <<'EOF'`)
	piles := map[string][]string{}
	nom := ""
	for _, ligne := range strings.Split(script, "\n") {
		if nom == "" {
			if m := debut.FindStringSubmatch(ligne); m != nil {
				nom = m[1]
				piles[nom] = nil
			}
			continue
		}
		if strings.TrimSpace(ligne) == "EOF" {
			nom = ""
			continue
		}
		piles[nom] = append(piles[nom], ligne)
	}
	return piles
}

func TestLesPilesPAMLaissentPasserLesComptesLocaux(t *testing.T) {
	piles := pilesPAM(t)
	for _, attendue := range []string{"login", "sshd", "gdm-password"} {
		if _, ok := piles[attendue]; !ok {
			t.Errorf("la pile « %s » n'est plus écrite par %s sous la forme attendue : "+
				"elle n'est donc plus contrôlée", attendue, scriptDInstallation)
		}
	}

	for nom, lignes := range piles {
		var auth [][]string
		for _, ligne := range lignes {
			nette := strings.TrimSpace(ligne)
			if nette == "" || strings.HasPrefix(nette, "#") {
				continue
			}
			nette = strings.TrimPrefix(nette, "-")
			if strings.HasPrefix(nette, "auth") && (len(nette) == 4 || nette[4] == ' ' || nette[4] == '\t') {
				auth = append(auth, []string{nette})
			}
		}
		if len(auth) == 0 {
			t.Errorf("pile « %s » : aucune ligne auth", nom)
			continue
		}

		// 1. Le module de Vaultaire ouvre la pile, et une seule fois.
		rang := -1
		for i, l := range auth {
			for _, module := range modulesVaultaire {
				if strings.Contains(l[0], module) {
					if rang >= 0 {
						t.Errorf("pile « %s » : deux lignes auth appellent un module Vaultaire", nom)
					}
					rang = i
				}
			}
		}
		if rang != 0 {
			t.Errorf("pile « %s » : le module Vaultaire n'est pas la première ligne auth (rang %d). "+
				"Une ligne placée avant lui décide du sort des comptes locaux à sa place.", nom, rang)
			continue
		}

		// 2. Son contrôle laisse passer PAM_IGNORE.
		controle := regexp.MustCompile(`\[([^\]]*)\]`).FindStringSubmatch(auth[0][0])
		if controle == nil {
			t.Errorf("pile « %s » : le module Vaultaire n'a plus de contrôle entre crochets (%s). "+
				"Un mot-clé comme « required » traite PAM_IGNORE autrement, et « requisite » coupe.", nom, auth[0][0])
			continue
		}
		if !regexp.MustCompile(`(^|\s)ignore=ignore(\s|$)`).MatchString(controle[1]) {
			t.Errorf("pile « %s » : le contrôle [%s] ne porte plus « ignore=ignore ». "+
				"PAM_IGNORE tombe alors dans « default » : root et les comptes locaux sont refusés "+
				"dès que l'agent est arrêté — la machine n'a plus de porte de secours.", nom, controle[1])
		}
		if !regexp.MustCompile(`(^|\s)success=done(\s|$)`).MatchString(controle[1]) {
			t.Errorf("pile « %s » : le contrôle [%s] ne porte plus « success=done »", nom, controle[1])
		}

		// 3. Et il y a bien quelque chose DERRIÈRE pour les authentifier.
		repli := false
		for _, l := range auth[1:] {
			if regexp.MustCompile(`^auth\s+(substack|include)\s+(system-auth|password-auth)\b`).MatchString(l[0]) {
				repli = true
			}
		}
		if !repli {
			t.Errorf("pile « %s » : aucune ligne « auth substack|include system-auth|password-auth » après le module. "+
				"PAM_IGNORE passerait, et personne ne vérifierait le mot de passe du compte local.", nom)
		}
	}
}

// corpsDe rend le corps d'une fonction C, de son accolade ouvrante à la
// fermante qui lui répond.
func corpsDe(t *testing.T, source, nom string) string {
	t.Helper()
	i := strings.Index(source, "int "+nom+"(")
	if i < 0 {
		t.Fatalf("fonction %s introuvable", nom)
	}
	ouverture := strings.Index(source[i:], "{")
	if ouverture < 0 {
		t.Fatalf("fonction %s sans corps", nom)
	}
	depart := i + ouverture
	profondeur := 0
	for j := depart; j < len(source); j++ {
		switch source[j] {
		case '{':
			profondeur++
		case '}':
			profondeur--
			if profondeur == 0 {
				return source[depart : j+1]
			}
		}
	}
	t.Fatalf("fonction %s : accolades non refermées", nom)
	return ""
}

// Le module rend PAM_IGNORE pour un compte hors du domaine AVANT de parler à
// l'agent. Après, un agent arrêté rendrait PAM_AUTHINFO_UNAVAIL pour tout le
// monde, root compris.
func TestLeModuleIgnoreUnCompteLocalAvantDeJoindreLAgent(t *testing.T) {
	for _, fichier := range []string{"pam_login_custom_module.c", "pam_ssh_auth_module.c"} {
		corps := corpsDe(t, lire(t, dossierDesModules+fichier), "pam_sm_authenticate")

		test := strings.Index(corps, "!is_vaultaire_user(username)")
		if test < 0 {
			t.Errorf("%s : pam_sm_authenticate ne teste plus « !is_vaultaire_user(username) »", fichier)
			continue
		}
		// Le retour qui suit ce test, dans le même bloc.
		fin := strings.Index(corps[test:], "}")
		if fin < 0 || !strings.Contains(corps[test:test+fin], "return PAM_IGNORE;") {
			t.Errorf("%s : un compte hors du domaine ne reçoit plus PAM_IGNORE. Toute autre valeur tombe dans "+
				"« default=die » : root ne peut plus se connecter.", fichier)
			continue
		}
		for _, appel := range []string{"vaultaire_socket_send_recv(", "vaultaire_socket_send(", "pam_get_authtok("} {
			if k := strings.Index(corps, appel); k >= 0 && k < test {
				t.Errorf("%s : « %s » est appelé AVANT le test du domaine. Un compte local dépendrait de "+
					"l'agent — ou se verrait demander son mot de passe par le module — avant d'être laissé à system-auth.",
					fichier, strings.TrimSuffix(appel, "("))
			}
		}
	}
}

// L'unité n'est plus écrite par le script, et l'agent est contrôlé AVANT que
// les piles PAM ne soient touchées.
func TestLeScriptControleLAgentAvantDeToucherAPAM(t *testing.T) {
	script := lire(t, scriptDInstallation)
	if strings.Contains(script, "cat > /etc/systemd/system/vaultaire_client.service") {
		t.Error("le script écrit de nouveau l'unité lui-même : elle peut porter un « --check » que le binaire " +
			"déposé ne connaît pas, et l'empêcher de démarrer. C'est « vaultaire_client --install-unit » qui l'écrit.")
	}
	controle := strings.Index(script, "/usr/bin/vaultaire_client --install-unit")
	if controle < 0 {
		t.Fatal("le script n'appelle plus « vaultaire_client --install-unit »")
	}
	configuration := strings.Index(script, "/etc/vaultaire_client/client_conf.json")
	if configuration < 0 || configuration > controle {
		t.Error("le contrôle est joué avant que client_conf.json ne soit écrit : il échouerait sur toute machine neuve")
	}
	for _, etape := range []string{"/etc/nsswitch.conf", `SSHD_CONF="/etc/ssh/sshd_config"`, "cat > /etc/pam.d/"} {
		k := strings.Index(script, etape)
		if k < 0 {
			t.Errorf("repère « %s » introuvable dans le script", etape)
			continue
		}
		if k < controle {
			t.Errorf("« %s » est modifié AVANT le contrôle de l'agent : un agent qui ne démarre pas "+
				"laisserait la machine avec des piles PAM sans repli", etape)
		}
	}
}

// Dans main, le contrôle répond avant tout ce qui lit, écrit ou se connecte.
func TestLeControleSortAvantToutLeReste(t *testing.T) {
	fichier, err := parser.ParseFile(token.NewFileSet(), "../main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var corps *ast.BlockStmt
	for _, d := range fichier.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "main" {
			corps = f.Body
		}
	}
	if corps == nil {
		t.Fatal("fonction main introuvable")
	}

	// Rang, dans main, de la première instruction qui appelle chaque fonction.
	rangDe := func(paquet, fonction string) int {
		for i, instruction := range corps.List {
			trouve := false
			ast.Inspect(instruction, func(n ast.Node) bool {
				appel, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := appel.Fun.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == paquet && sel.Sel.Name == fonction {
						trouve = true
					}
				}
				return true
			})
			if trouve {
				return i
			}
		}
		return -1
	}

	controle := rangDe("controle", "Verifier")
	if controle < 0 {
		t.Fatal("main n'appelle plus controle.Verifier : « --check » ne contrôle plus rien")
	}
	if rangDe("flag", "Parse") > controle {
		t.Error("les options sont lues après le contrôle")
	}
	for _, apres := range [][2]string{
		{"config", "LoadConfig"},
		{"yaml_vaultaire", "ReadYAMLFile"},
		{"serveurcommunication", "DemarrerTunnelMachine"},
		{"pamcommunication", "UnixSocketServer"},
		{"pamcommunication", "StartUIDAllocationServer"},
	} {
		r := rangDe(apres[0], apres[1])
		if r < 0 {
			t.Errorf("repère %s.%s introuvable dans main", apres[0], apres[1])
			continue
		}
		if r <= controle {
			t.Errorf("%s.%s est appelé avant que « --check » ne réponde : le contrôle mourrait sur ce qu'il doit "+
				"constater, ou ouvrirait ce qu'il promet de ne pas ouvrir", apres[0], apres[1])
		}
	}
}
